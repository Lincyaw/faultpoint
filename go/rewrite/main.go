// Command fprewrite copies a Go module and places call, branch, check, loop and clock points in
// the copy, using type information to recognise errors, booleans and clock reads.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/printer"
	"go/token"
	"go/types"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/mod/modfile"
	"golang.org/x/tools/go/ast/astutil"
	"golang.org/x/tools/go/packages"
)

const (
	sdkModule    = "faultpoint"
	manifestFile = "faultpoint-manifest.json"
	registryFile = "faultpoint_errors.go"
	codeWidth    = 120
)

var errorType = types.Universe.Lookup("error").Type()

// PointEntry is one point of the manifest, as spec/manifest.schema.json defines.
type PointEntry struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Function string `json:"function"`
	Code     string `json:"code"`
}

// Manifest lists every point placed in a service.
type Manifest struct {
	Service  string       `json:"service"`
	Language string       `json:"language"`
	Points   []PointEntry `json:"points"`
}

type function struct {
	name     string
	context  func() ast.Expr
	check    string
	literals int
}

// placer places the points of one file.
type placer struct {
	service   string
	path      string
	fset      *token.FileSet
	info      *types.Info
	functions []*function
	anchors   map[ast.Node]string
	ordinals  map[string]int
	points    []PointEntry
}

func (p *placer) text(node ast.Node) string {
	var buffer bytes.Buffer
	if err := printer.Fprint(&buffer, p.fset, node); err != nil {
		log.Fatal(err)
	}
	return buffer.String()
}

func (p *placer) current() *function { return p.functions[len(p.functions)-1] }

func (p *placer) place(kind string, node ast.Node, anchor string, hashed bool) string {
	name := "<package>"
	if len(p.functions) > 0 {
		name = p.current().name
	}
	locator := p.path + ":" + name
	if hashed {
		digest := sha256.Sum256([]byte(anchor))
		base := locator + "#" + hex.EncodeToString(digest[:])[:8]
		ordinal := p.ordinals[base]
		p.ordinals[base]++
		locator = base
		if ordinal > 0 {
			locator = base + "." + strconv.Itoa(ordinal)
		}
	}
	id := p.service + ":" + kind + ":" + locator
	code := strings.SplitN(anchor, "\n", 2)[0]
	if len(code) > codeWidth {
		code = code[:codeWidth]
	}
	p.points = append(p.points, PointEntry{ID: id, Kind: kind, File: p.path,
		Line: p.fset.Position(node.Pos()).Line, Function: name, Code: code})
	return id
}

func (p *placer) contextOf(parameters *ast.FieldList) func() ast.Expr {
	for _, field := range parameters.List {
		for _, name := range field.Names {
			if name.Name == "_" {
				continue
			}
			named, ok := p.info.TypeOf(name).(*types.Named)
			if ok && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "context" && named.Obj().Name() == "Context" {
				identifier := name.Name
				return func() ast.Expr { return ast.NewIdent(identifier) }
			}
			pointer, ok := p.info.TypeOf(name).(*types.Pointer)
			if !ok {
				continue
			}
			named, ok = pointer.Elem().(*types.Named)
			if ok && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "net/http" && named.Obj().Name() == "Request" {
				identifier := name.Name
				return func() ast.Expr {
					return &ast.CallExpr{Fun: &ast.SelectorExpr{X: ast.NewIdent(identifier), Sel: ast.NewIdent("Context")}}
				}
			}
		}
	}
	if len(p.functions) > 0 {
		return p.current().context
	}
	return func() ast.Expr { return ast.NewIdent("nil") }
}

// ownReturns are the return statements of a function body, not of the literals it holds.
func ownReturns(body *ast.BlockStmt) []*ast.ReturnStmt {
	var returns []*ast.ReturnStmt
	ast.Inspect(body, func(node ast.Node) bool {
		switch statement := node.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ReturnStmt:
			returns = append(returns, statement)
		}
		return true
	})
	return returns
}

// checkable is whether a function's only result is an unnamed bool that some return computes.
func (p *placer) checkable(signature *ast.FuncType, body *ast.BlockStmt) bool {
	results := signature.Results
	if body == nil || results == nil || len(results.List) != 1 || len(results.List[0].Names) > 0 {
		return false
	}
	if !types.Identical(p.info.TypeOf(results.List[0].Type), types.Typ[types.Bool]) {
		return false
	}
	for _, statement := range ownReturns(body) {
		if len(statement.Results) == 1 && p.info.Types[statement.Results[0]].Value == nil {
			return true
		}
	}
	return false
}

func (p *placer) enter(name string, signature *ast.FuncType, body *ast.BlockStmt, node ast.Node) {
	entered := &function{name: name, context: p.contextOf(signature.Params)}
	p.functions = append(p.functions, entered)
	if p.checkable(signature, body) {
		entered.check = p.place("check", node, p.text(signature), false)
	}
}

func (p *placer) call(name string, point string, arguments ...ast.Expr) *ast.CallExpr {
	return &ast.CallExpr{
		Fun:  &ast.SelectorExpr{X: ast.NewIdent(sdkModule), Sel: ast.NewIdent(name)},
		Args: append([]ast.Expr{p.current().context(), &ast.BasicLit{Kind: token.STRING, Value: strconv.Quote(point)}}, arguments...),
	}
}

// errorVariable is the variable of an `err != nil` condition whose type is exactly error.
func (p *placer) errorVariable(condition ast.Expr) *ast.Ident {
	binary, ok := condition.(*ast.BinaryExpr)
	if !ok || binary.Op != token.NEQ {
		return nil
	}
	variable, ok := binary.X.(*ast.Ident)
	if !ok || !p.info.Types[binary.Y].IsNil() || !types.Identical(p.info.TypeOf(variable), errorType) {
		return nil
	}
	return variable
}

// guardsError is whether a block returns a non-nil error directly.
func (p *placer) guardsError(body *ast.BlockStmt) bool {
	for _, statement := range body.List {
		returned, ok := statement.(*ast.ReturnStmt)
		if !ok || len(returned.Results) == 0 {
			continue
		}
		last := returned.Results[len(returned.Results)-1]
		value := p.info.Types[last]
		if !value.IsNil() && value.Type != nil && types.Implements(value.Type, errorType.Underlying().(*types.Interface)) {
			return true
		}
	}
	return false
}

func (p *placer) constantLoop(node ast.Node) bool {
	switch loop := node.(type) {
	case *ast.ForStmt:
		binary, ok := loop.Cond.(*ast.BinaryExpr)
		return ok && p.info.Types[binary.Y].Value != nil
	case *ast.RangeStmt:
		return p.info.Types[loop.X].Value != nil
	}
	return false
}

func (p *placer) clockCall(call *ast.CallExpr) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	callee, ok := p.info.Uses[selector.Sel].(*types.Func)
	return ok && callee.Pkg() != nil && callee.Pkg().Path() == "time" && callee.Name() == "Now"
}

func (p *placer) pre(cursor *astutil.Cursor) bool {
	switch node := cursor.Node().(type) {
	case *ast.FuncDecl:
		name := node.Name.Name
		if node.Recv != nil && len(node.Recv.List) == 1 {
			name = strings.TrimLeft(p.text(node.Recv.List[0].Type), "*") + "." + name
		}
		p.enter(name, node.Type, node.Body, node)
	case *ast.FuncLit:
		outer := "<package>"
		if len(p.functions) > 0 {
			outer = p.current().name
			p.current().literals++
			outer += ".func" + strconv.Itoa(p.current().literals)
		}
		p.enter(outer, node.Type, node.Body, node)
	case *ast.IfStmt:
		p.anchors[node] = p.text(node.Cond)
	case *ast.ForStmt, *ast.RangeStmt, *ast.CallExpr:
		p.anchors[node] = p.text(node)
	}
	return true
}

func (p *placer) post(cursor *astutil.Cursor) bool {
	switch node := cursor.Node().(type) {
	case *ast.FuncDecl, *ast.FuncLit:
		p.functions = p.functions[:len(p.functions)-1]
	case *ast.ReturnStmt:
		if len(p.functions) > 0 && p.current().check != "" && len(node.Results) == 1 {
			node.Results[0] = p.call("Check", p.current().check, node.Results[0])
		}
	case *ast.IfStmt:
		if len(p.functions) == 0 {
			break
		}
		if variable := p.errorVariable(node.Cond); variable != nil {
			point := p.place("call", node, p.anchors[node], true)
			node.Cond = p.call("Failed", point, &ast.UnaryExpr{Op: token.AND, X: ast.NewIdent(variable.Name)})
		} else if p.guardsError(node.Body) {
			point := p.place("branch", node, p.anchors[node], true)
			node.Cond = p.call("Branch", point, node.Cond)
		}
	case *ast.ForStmt:
		if len(p.functions) > 0 && !p.constantLoop(node) {
			p.placeLoop(node, node.Body)
		}
	case *ast.RangeStmt:
		if len(p.functions) > 0 && !p.constantLoop(node) {
			p.placeLoop(node, node.Body)
		}
	case *ast.CallExpr:
		if len(p.functions) > 0 && p.clockCall(node) {
			point := p.place("clock", node, p.anchors[node], true)
			cursor.Replace(p.call("Clock", point, node))
		}
	}
	return true
}

func (p *placer) placeLoop(node ast.Node, body *ast.BlockStmt) {
	point := p.place("loop", node, p.anchors[node], true)
	body.List = append([]ast.Stmt{&ast.ExprStmt{X: p.call("Loop", point)}}, body.List...)
}

func copyTree(source, target string) error {
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		if entry.IsDir() && (entry.Name() == ".git" || entry.Name() == "vendor") {
			return filepath.SkipDir
		}
		destination := filepath.Join(target, relative)
		if entry.IsDir() {
			return os.MkdirAll(destination, 0o755)
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(destination, content, 0o644)
	})
}

// registry is the source of a file that registers a package's error variables by name.
func registry(pkg *packages.Package) []byte {
	scope := pkg.Types.Scope()
	var lines []string
	for _, name := range scope.Names() {
		variable, ok := scope.Lookup(name).(*types.Var)
		if ok && types.Identical(variable.Type(), errorType) {
			lines = append(lines, fmt.Sprintf("\t%s.RegisterError(%q, %s)", sdkModule, pkg.PkgPath+"."+name, name))
		}
	}
	if len(lines) == 0 {
		return nil
	}
	source := fmt.Sprintf("// Code generated by fprewrite. DO NOT EDIT.\n\npackage %s\n\nimport %q\n\nfunc init() {\n%s\n}\n",
		pkg.Name, sdkModule, strings.Join(lines, "\n"))
	formatted, err := format.Source([]byte(source))
	if err != nil {
		log.Fatal(err)
	}
	return formatted
}

func requireSDK(target, sdk string) error {
	path := filepath.Join(target, "go.mod")
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	module, err := modfile.Parse(path, content, nil)
	if err != nil {
		return err
	}
	if err := module.AddRequire(sdkModule, "v0.0.0"); err != nil {
		return err
	}
	if err := module.AddReplace(sdkModule, "", sdk, ""); err != nil {
		return err
	}
	formatted, err := module.Format()
	if err != nil {
		return err
	}
	return os.WriteFile(path, formatted, 0o644)
}

func main() {
	service := flag.String("service", "", "the service the points belong to")
	source := flag.String("source", "", "the Go module to instrument")
	target := flag.String("target", "", "where the instrumented copy is written")
	sdk := flag.String("sdk", "", "the path of the faultpoint Go module")
	flag.Parse()
	if *service == "" || *source == "" || *target == "" || *sdk == "" {
		flag.Usage()
		os.Exit(2)
	}
	sourceRoot, err := filepath.Abs(*source)
	if err != nil {
		log.Fatal(err)
	}
	sdkRoot, err := filepath.Abs(*sdk)
	if err != nil {
		log.Fatal(err)
	}
	if err := copyTree(sourceRoot, *target); err != nil {
		log.Fatal(err)
	}
	config := &packages.Config{Dir: sourceRoot, Mode: packages.NeedName | packages.NeedFiles |
		packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo}
	loaded, err := packages.Load(config, "./...")
	if err != nil {
		log.Fatal(err)
	}
	if packages.PrintErrors(loaded) > 0 {
		os.Exit(1)
	}
	manifest := Manifest{Service: *service, Language: "go", Points: []PointEntry{}}
	for _, pkg := range loaded {
		for _, file := range pkg.Syntax {
			original := pkg.Fset.Position(file.Pos()).Filename
			relative, err := filepath.Rel(sourceRoot, original)
			if err != nil {
				log.Fatal(err)
			}
			p := &placer{service: *service, path: filepath.ToSlash(relative), fset: pkg.Fset,
				info: pkg.TypesInfo, anchors: map[ast.Node]string{}, ordinals: map[string]int{}}
			astutil.Apply(file, p.pre, p.post)
			if len(p.points) == 0 {
				continue
			}
			astutil.AddImport(pkg.Fset, file, sdkModule)
			var buffer bytes.Buffer
			if err := format.Node(&buffer, pkg.Fset, file); err != nil {
				log.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(*target, relative), buffer.Bytes(), 0o644); err != nil {
				log.Fatal(err)
			}
			manifest.Points = append(manifest.Points, p.points...)
		}
		if source := registry(pkg); source != nil {
			directory, err := filepath.Rel(sourceRoot, filepath.Dir(pkg.GoFiles[0]))
			if err != nil {
				log.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(*target, directory, registryFile), source, 0o644); err != nil {
				log.Fatal(err)
			}
		}
	}
	if err := requireSDK(*target, sdkRoot); err != nil {
		log.Fatal(err)
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(*target, manifestFile), append(encoded, '\n'), 0o644); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%d points placed in %s\n", len(manifest.Points), *target)
}
