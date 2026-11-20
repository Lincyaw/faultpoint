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
	registryFile = "faultpoint_errors.go"
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

// loadPackages loads the packages of a module as the go command resolves them from its directory.
func loadPackages(dir string) []*packages.Package {
	config := &packages.Config{Dir: dir, Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
		packages.NeedTypes | packages.NeedTypesInfo}
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

// rewritten is a package written into the copy, which gets its init once every package is known.
type rewritten struct {
	dir  string
	name string
}

// instrumentPackage writes the rewritten files of a package of a module into the module's copy, with its error
// registry, and returns the points it placed and the plugin packages it now imports.
func instrumentPackage(service string, source module, copied string, config Config, pkg *packages.Package) ([]PointEntry, []string) {
	var placed []PointEntry
	var used []string
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
		var content bytes.Buffer
		if err := format.Node(&content, pkg.Fset, file); err != nil {
			log.Fatal(err)
		}
		writeFile(filepath.Join(copied, relative), content.Bytes())
		placed, used = append(placed, points...), append(used, imports...)
	}
	if registry := errorRegistry(pkg); registry != nil && slices.Contains(config.Plugins, pointsPlugin) && config.Placement.Errors {
		writeFile(filepath.Join(copied, relativePath(source.dir, filepath.Dir(pkg.GoFiles[0])), registryFile), registry)
		used = append(used, pointsPackage)
	}
	return placed, used
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
	root, targetRoot, sdkRoot := commonDir(modules), absolutePath(*target), absolutePath(*sdk)
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
	var written []rewritten
	used := map[string]bool{}
	for index, known := range modules {
		copies[index] = filepath.Join(targetRoot, relativePath(root, known.dir))
		if err := copyTree(known.dir, copies[index]); err != nil {
			log.Fatal(err)
		}
		for _, pkg := range loadPackages(known.dir) {
			if len(pkg.GoFiles) == 0 {
				continue
			}
			points, imports := instrumentPackage(*service, known, copies[index], config, pkg)
			manifest.Points = append(manifest.Points, points...)
			for _, imported := range imports {
				used[imported] = true
			}
			written = append(written, rewritten{name: pkg.Name,
				dir: filepath.Join(copies[index], relativePath(known.dir, filepath.Dir(pkg.GoFiles[0])))})
		}
	}
	plugins := slices.Sorted(maps.Keys(used))
	for _, pkg := range written {
		writeFile(filepath.Join(pkg.dir, initFile), packageInit(pkg.name, plugins, slices.Contains(config.Plugins, httpPlugin)))
	}
	if workspace := workspaceFile(absolutePath(*source)); workspace != "" {
		writeWorkspace(workspace, targetRoot, copies, sdkRoot)
	} else {
		for _, copied := range copies {
			requireSDK(copied, sdkRoot)
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
