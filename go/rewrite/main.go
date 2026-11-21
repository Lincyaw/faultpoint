// Command fprewrite places fault points in a build copy of a Go module and of the local modules it imports, and
// wires their net/http, gin, database/sql, pgx and go-redis boundaries to the faultpoint adapters, so that the
// service's own source never contains the SDK; its scan command writes the manifest of the same points without a copy.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"io/fs"
	"log"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/tools/go/ast/astutil"
	"golang.org/x/tools/go/packages"
)

const (
	manifestFile = "faultpoint-manifest.json"
	registryFile = "faultpoint_registry.go"
	initFile     = "faultpoint_init.go"
	usage        = `usage:
  fprewrite instrument -service NAME -source DIR -target DIR -sdk DIR [-config FILE]
  fprewrite scan -service NAME -source DIR [-manifest FILE] [-config FILE]
The local modules the source module imports, through its go.work or through directory replacements, are
instrumented with it; the target holds every module at its place relative to their common directory, with a
go.work beside them when the source has one.`
)

// Config is the file FAULTPOINT_CONFIG names; the rewriter reads the plugins to wire and the placement.
type Config struct {
	Plugins   []string                   `json:"plugins"`
	Options   map[string]json.RawMessage `json:"options"`
	Placement Placement                  `json:"placement"`
}

func readConfig(path string) Config {
	config := Config{Plugins: []string{pointsPlugin, httpPlugin, ginPlugin, sqlPlugin, pgxPlugin, redisPlugin},
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

// loadPackages loads packages with their syntax and types as the go command resolves them from a directory.
func loadPackages(dir string, patterns ...string) []*packages.Package {
	config := &packages.Config{Dir: dir, Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
		packages.NeedTypes | packages.NeedTypesInfo | packages.NeedModule}
	loaded, err := packages.Load(config, patterns...)
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

// writeManifest writes a manifest with its error names sorted, each once.
func writeManifest(path string, manifest Manifest) {
	slices.Sort(manifest.Errors)
	manifest.Errors = slices.Compact(manifest.Errors)
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	writeFile(path, append(encoded, '\n'))
}

// rewritten is a package written into the copy, which gets its init once every package is known.
type rewritten struct {
	dir  string
	name string
}

// rewriteFile adds the imports a rewritten file now needs and prints it.
func rewriteFile(pkg *packages.Package, file *ast.File, imports []string) []byte {
	for _, imported := range imports {
		astutil.AddImport(pkg.Fset, file, imported)
	}
	var content bytes.Buffer
	if err := format.Node(&content, pkg.Fset, file); err != nil {
		log.Fatal(err)
	}
	return content.Bytes()
}

// instrumentPackage writes the rewritten files of a package of a module into the module's copy, with its registry,
// adds its points and registered errors to the manifest, and returns the plugin packages it now imports.
func instrumentPackage(service string, source module, copied string, config Config, pkg *packages.Package, manifest *Manifest) []string {
	var used []string
	var placed []PointEntry
	for _, file := range pkg.Syntax {
		relative := relativePath(source.dir, pkg.Fset.Position(file.Pos()).Filename)
		var points []PointEntry
		if slices.Contains(config.Plugins, pointsPlugin) {
			points = placePoints(service, source.prefix+relative, config.Placement, pkg, file)
		}
		imports := wireBoundaries(pkg.TypesInfo, config.Plugins, file)
		if len(points) > 0 {
			imports = append(imports, pointsPackage)
		}
		if len(imports) > 0 {
			writeFile(filepath.Join(copied, relative), rewriteFile(pkg, file, imports))
			placed, used = append(placed, points...), append(used, imports...)
		}
	}
	manifest.Points = append(manifest.Points, placed...)
	if registry, names := packageRegistry(pkg, config.Placement, placed); registry != nil {
		writeFile(filepath.Join(copied, relativePath(source.dir, filepath.Dir(pkg.GoFiles[0])), registryFile), registry)
		manifest.Errors = append(manifest.Errors, names...)
	}
	return used
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
	sourceDir := absolutePath(*source)
	graph := importGraph(sourceDir)
	modules := localModules(sourceDir, graph)
	libraries := map[string]ScopeEntry{}
	if slices.Contains(config.Plugins, pointsPlugin) {
		libraries = scopedLibraries(graph, config.Placement)
	}
	root, targetRoot, sdkRoot := commonDir(modules), absolutePath(*target), absolutePath(*sdk)
	if slices.Contains(config.Plugins, redisPlugin) {
		checkCommandTable(sdkRoot)
	}
	if _, err := os.Stat(targetRoot); !errors.Is(err, fs.ErrNotExist) {
		log.Fatalf("the target %s exists; fprewrite writes a fresh copy", targetRoot)
	}
	for _, known := range modules {
		if strings.HasPrefix(targetRoot, known.dir+string(filepath.Separator)) {
			log.Fatalf("the target %s lies inside the module %s", targetRoot, known.dir)
		}
	}
	manifest := Manifest{Service: *service, Language: "go", Points: []PointEntry{}, Errors: []string{}}
	copies := make([]string, len(modules))
	var written []rewritten
	used := map[string]bool{}
	for index, known := range modules {
		copies[index] = filepath.Join(targetRoot, relativePath(root, known.dir))
		if err := copyTree(known.dir, copies[index]); err != nil {
			log.Fatal(err)
		}
		for _, pkg := range loadPackages(known.dir, "./...") {
			if len(pkg.GoFiles) == 0 {
				continue
			}
			for _, imported := range instrumentPackage(*service, known, copies[index], config, pkg, &manifest) {
				used[imported] = true
			}
			written = append(written, rewritten{name: pkg.Name,
				dir: filepath.Join(copies[index], relativePath(known.dir, filepath.Dir(pkg.GoFiles[0])))})
		}
	}
	if len(libraries) > 0 {
		used[pointsPackage] = true
	}
	plugins := slices.Sorted(maps.Keys(used))
	sentinels := packageErrors(sourceDir, config.Placement.ErrorPackages)
	for _, pkg := range written {
		writeFile(filepath.Join(pkg.dir, initFile), packageInit(pkg.name, plugins, slices.Contains(config.Plugins, httpPlugin), sentinels))
	}
	for _, sentinel := range sentinels {
		manifest.Errors = append(manifest.Errors, sentinel.Name)
	}
	builds := filepath.Join(copies[0], "go.mod")
	if workspace := workspaceFile(sourceDir); workspace != "" {
		writeWorkspace(workspace, targetRoot, copies, sdkRoot)
		builds = filepath.Join(targetRoot, "go.work")
	} else {
		for _, copied := range copies {
			requireSDK(copied, sdkRoot)
		}
	}
	if len(libraries) > 0 {
		addReplacements(builds, copyLibraries(*service, config.Placement, libraries, copies[0], targetRoot, &manifest))
	}
	writeManifest(filepath.Join(copies[0], manifestFile), manifest)
	fmt.Printf("%d points placed in %d modules and %d dependency packages; the service is at %s\n",
		len(manifest.Points), len(modules), len(libraries), copies[0])
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
	manifest := Manifest{Service: *service, Language: "go", Points: []PointEntry{}, Errors: []string{}}
	sourceDir := absolutePath(*source)
	graph := importGraph(sourceDir)
	for _, known := range localModules(sourceDir, graph) {
		for _, pkg := range loadPackages(known.dir, "./...") {
			for _, file := range pkg.Syntax {
				relative := known.prefix + relativePath(known.dir, pkg.Fset.Position(file.Pos()).Filename)
				manifest.Points = append(manifest.Points, placePoints(*service, relative, config.Placement, pkg, file)...)
			}
			_, names := packageRegistry(pkg, config.Placement, nil)
			manifest.Errors = append(manifest.Errors, names...)
		}
	}
	if libraries := scopedLibraries(graph, config.Placement); len(libraries) > 0 {
		scanLibraries(*service, sourceDir, config.Placement, libraries, &manifest)
	}
	for _, sentinel := range packageErrors(sourceDir, config.Placement.ErrorPackages) {
		manifest.Errors = append(manifest.Errors, sentinel.Name)
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
