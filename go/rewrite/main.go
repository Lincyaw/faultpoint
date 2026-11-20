// Command fprewrite places fault points in a build copy of a Go module and of the local modules it replaces, and
// wires their net/http, database/sql, pgx and go-redis boundaries to the faultpoint adapters, so that the service's
// own source never contains the SDK; its scan command writes the manifest of the same points without a copy.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/format"
	"io/fs"
	"log"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/mod/modfile"
	"golang.org/x/tools/go/ast/astutil"
	"golang.org/x/tools/go/packages"
)

const (
	manifestFile = "faultpoint-manifest.json"
	registryFile = "faultpoint_errors.go"
	initFile     = "faultpoint_init.go"
	usage        = `usage:
  fprewrite instrument -service NAME -source DIR -target DIR -sdk DIR [-config FILE]
  fprewrite scan -service NAME -source DIR [-manifest FILE] [-config FILE]
The local modules the source module replaces, directly or through each other, are instrumented with it; the
target holds every module at its place relative to their common directory.`
)

// module is a Go module the rewriter instruments; a point in a module other than the service's own is identified by
// the module path, since its files lie outside the service.
type module struct {
	dir    string
	prefix string
}

// localModules are the source module and the local modules its go.mod replaces with directories, transitively.
func localModules(source string) []module {
	modules := []module{{dir: source}}
	for index := 0; index < len(modules); index++ {
		path := filepath.Join(modules[index].dir, "go.mod")
		content, err := os.ReadFile(path)
		if err != nil {
			log.Fatal(err)
		}
		parsed, err := modfile.Parse(path, content, nil)
		if err != nil {
			log.Fatal(err)
		}
		if index > 0 {
			modules[index].prefix = parsed.Module.Mod.Path + "/"
		}
		for _, replaced := range parsed.Replace {
			dir := filepath.Clean(filepath.Join(modules[index].dir, replaced.New.Path))
			local := replaced.New.Version == "" && modfile.IsDirectoryPath(replaced.New.Path)
			if local && !slices.ContainsFunc(modules, func(known module) bool { return known.dir == dir }) {
				modules = append(modules, module{dir: dir})
			}
		}
	}
	return modules
}

// commonDir is the deepest directory that holds every module.
func commonDir(modules []module) string {
	root := modules[0].dir
	for _, known := range modules {
		for !strings.HasPrefix(known.dir+string(filepath.Separator), root+string(filepath.Separator)) {
			root = filepath.Dir(root)
		}
	}
	return root
}

// Config is the file FAULTPOINT_CONFIG names; the rewriter reads the plugins to wire and the placement.
type Config struct {
	Plugins   []string                   `json:"plugins"`
	Options   map[string]json.RawMessage `json:"options"`
	Placement Placement                  `json:"placement"`
}

func readConfig(path string) Config {
	config := Config{Plugins: []string{pointsPlugin, httpPlugin, sqlPlugin, pgxPlugin, redisPlugin},
		Placement: Placement{Branch: true, Call: true, Check: true, Loop: true, Clock: []string{"time.Now"}, Errors: true}}
	if path == "" {
		return config
	}
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		log.Fatalf("invalid configuration in %s: %v", path, err)
	}
	for _, plugin := range config.Plugins {
		if _, known := pluginPackages[plugin]; !known {
			log.Fatalf("the configuration enables %q, which is not a Go plugin: %v", plugin, slices.Sorted(maps.Keys(pluginPackages)))
		}
	}
	return config
}

// loadPackages loads a module on its own, as the copy builds it, without a go.work around the source.
func loadPackages(source string) []*packages.Package {
	config := &packages.Config{Dir: source, Env: append(os.Environ(), "GOWORK=off"), Mode: packages.NeedName |
		packages.NeedFiles | packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo}
	loaded, err := packages.Load(config, "./...")
	if err != nil {
		log.Fatal(err)
	}
	if packages.PrintErrors(loaded) > 0 {
		os.Exit(1)
	}
	return loaded
}

func relativePath(root, path string) string {
	relative, err := filepath.Rel(root, path)
	if err != nil {
		log.Fatal(err)
	}
	return filepath.ToSlash(relative)
}

func absolutePath(path string) string {
	absolute, err := filepath.Abs(path)
	if err != nil {
		log.Fatal(err)
	}
	return absolute
}

func writeFile(path string, content []byte) {
	if err := os.WriteFile(path, content, 0o644); err != nil {
		log.Fatal(err)
	}
}

func writeManifest(path string, manifest Manifest) {
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	writeFile(path, append(encoded, '\n'))
}

// copyTree copies a module without its version control and vendor directories.
func copyTree(source, target string) error {
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() && (entry.Name() == ".git" || entry.Name() == "vendor") {
			return filepath.SkipDir
		}
		destination := filepath.Join(target, relativePath(source, path))
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

// requireSDK makes the copy's module require the SDK from its local path.
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
	if err := module.AddRequire(corePackage, "v0.0.0"); err != nil {
		return err
	}
	if err := module.AddReplace(corePackage, "", sdk, ""); err != nil {
		return err
	}
	formatted, err := module.Format()
	if err != nil {
		return err
	}
	return os.WriteFile(path, formatted, 0o644)
}

// instrumentPackage writes the rewritten files of a package of a module into the module's copy, with its error
// registry and its init, and returns the points it placed; a directory of test files only has no package to rewrite.
func instrumentPackage(service string, source module, copied string, config Config, pkg *packages.Package) []PointEntry {
	if len(pkg.GoFiles) == 0 {
		return nil
	}
	var placed []PointEntry
	for _, file := range pkg.Syntax {
		relative := relativePath(source.dir, pkg.Fset.Position(file.Pos()).Filename)
		points := placePoints(service, source.prefix+relative, config, pkg, file)
		imports := wireBoundaries(pkg.TypesInfo, config.Plugins, file)
		if len(points) > 0 {
			imports = append(imports, pointsPackage)
		}
		if len(imports) == 0 {
			continue
		}
		for _, imported := range imports {
			astutil.AddImport(pkg.Fset, file, imported)
		}
		var rewritten bytes.Buffer
		if err := format.Node(&rewritten, pkg.Fset, file); err != nil {
			log.Fatal(err)
		}
		writeFile(filepath.Join(copied, relative), rewritten.Bytes())
		placed = append(placed, points...)
	}
	directory := filepath.Join(copied, relativePath(source.dir, filepath.Dir(pkg.GoFiles[0])))
	if slices.Contains(config.Plugins, pointsPlugin) && config.Placement.Errors {
		if registry := errorRegistry(pkg); registry != nil {
			writeFile(filepath.Join(directory, registryFile), registry)
		}
	}
	writeFile(filepath.Join(directory, initFile), packageInit(pkg.Name, config.Plugins))
	return placed
}

func instrument(arguments []string) {
	flags := flag.NewFlagSet("instrument", flag.ExitOnError)
	service := flags.String("service", "", "the service the points belong to")
	source := flags.String("source", "", "the Go module to instrument")
	target := flags.String("target", "", "where the instrumented copy is written; it must not exist")
	sdk := flags.String("sdk", "", "the path of the faultpoint Go module")
	configPath := flags.String("config", "", "the faultpoint configuration, for its plugins and placement")
	flags.Parse(arguments)
	if *service == "" || *source == "" || *target == "" || *sdk == "" {
		log.Fatal(usage)
	}
	config := readConfig(*configPath)
	modules := localModules(absolutePath(*source))
	root, targetRoot := commonDir(modules), absolutePath(*target)
	if _, err := os.Stat(targetRoot); !errors.Is(err, fs.ErrNotExist) {
		log.Fatalf("the target %s exists; fprewrite writes a fresh copy", targetRoot)
	}
	for _, known := range modules {
		if strings.HasPrefix(targetRoot, known.dir+string(filepath.Separator)) {
			log.Fatalf("the target %s lies inside the module %s", targetRoot, known.dir)
		}
	}
	manifest := Manifest{Service: *service, Language: "go", Points: []PointEntry{}}
	copies := make([]string, len(modules))
	for index, known := range modules {
		copies[index] = filepath.Join(targetRoot, relativePath(root, known.dir))
		if err := copyTree(known.dir, copies[index]); err != nil {
			log.Fatal(err)
		}
		for _, pkg := range loadPackages(known.dir) {
			manifest.Points = append(manifest.Points, instrumentPackage(*service, known, copies[index], config, pkg)...)
		}
		if err := requireSDK(copies[index], absolutePath(*sdk)); err != nil {
			log.Fatal(err)
		}
	}
	for _, copied := range copies {
		tidy := exec.Command("go", "mod", "tidy")
		tidy.Dir, tidy.Env, tidy.Stdout, tidy.Stderr = copied, append(os.Environ(), "GOWORK=off"), os.Stderr, os.Stderr
		if err := tidy.Run(); err != nil {
			log.Fatalf("go mod tidy in %s: %v", copied, err)
		}
	}
	writeManifest(filepath.Join(copies[0], manifestFile), manifest)
	fmt.Printf("%d points placed in %d modules; the service is at %s\n", len(manifest.Points), len(modules), copies[0])
}

func scan(arguments []string) {
	flags := flag.NewFlagSet("scan", flag.ExitOnError)
	service := flags.String("service", "", "the service the points belong to")
	source := flags.String("source", "", "the Go module to scan")
	manifestPath := flags.String("manifest", manifestFile, "where the manifest is written")
	configPath := flags.String("config", "", "the faultpoint configuration, for its plugins and placement")
	flags.Parse(arguments)
	if *service == "" || *source == "" {
		log.Fatal(usage)
	}
	config := readConfig(*configPath)
	manifest := Manifest{Service: *service, Language: "go", Points: []PointEntry{}}
	for _, known := range localModules(absolutePath(*source)) {
		for _, pkg := range loadPackages(known.dir) {
			for _, file := range pkg.Syntax {
				relative := known.prefix + relativePath(known.dir, pkg.Fset.Position(file.Pos()).Filename)
				manifest.Points = append(manifest.Points, placePoints(*service, relative, config, pkg, file)...)
			}
		}
	}
	writeManifest(*manifestPath, manifest)
	fmt.Printf("%d points listed in %s\n", len(manifest.Points), *manifestPath)
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("fprewrite: ")
	if len(os.Args) < 2 {
		log.Fatal(usage)
	}
	switch os.Args[1] {
	case "instrument":
		instrument(os.Args[2:])
	case "scan":
		scan(os.Args[2:])
	default:
		log.Fatal(usage)
	}
}
