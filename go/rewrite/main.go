// Command fprewrite places fault points in a build copy of a Go module and wires its net/http and database/sql
// boundaries to the faultpoint adapters, so that the service's own source never contains the SDK; its scan
// command writes the manifest of the same points without a copy.
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
	wiringFile   = "faultpoint_main.go"
	usage        = `usage:
  fprewrite instrument -service NAME -source DIR -target DIR -sdk DIR [-config FILE]
  fprewrite scan -service NAME -source DIR [-manifest FILE] [-config FILE]`
)

// Config is the file FAULTPOINT_CONFIG names; the rewriter reads the plugins to wire and the placement.
type Config struct {
	Plugins   []string                   `json:"plugins"`
	Options   map[string]json.RawMessage `json:"options"`
	Placement Placement                  `json:"placement"`
}

func readConfig(path string) Config {
	config := Config{Plugins: []string{pointsPlugin, httpPlugin, sqlPlugin},
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
			log.Fatalf("the configuration enables %q, which is not a Go plugin: points, http or sql", plugin)
		}
	}
	return config
}

func loadPackages(source string) []*packages.Package {
	config := &packages.Config{Dir: source, Mode: packages.NeedName | packages.NeedFiles |
		packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo}
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

// instrumentPackage writes the rewritten files of a package into the copy, with its error registry and, for a
// main package, its wiring, and returns the points it placed.
func instrumentPackage(service, sourceRoot, target string, config Config, pkg *packages.Package) []PointEntry {
	var placed []PointEntry
	for _, file := range pkg.Syntax {
		relative := relativePath(sourceRoot, pkg.Fset.Position(file.Pos()).Filename)
		points := placePoints(service, relative, config, pkg, file)
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
		writeFile(filepath.Join(target, relative), rewritten.Bytes())
		placed = append(placed, points...)
	}
	directory := filepath.Join(target, relativePath(sourceRoot, filepath.Dir(pkg.GoFiles[0])))
	if slices.Contains(config.Plugins, pointsPlugin) && config.Placement.Errors {
		if registry := errorRegistry(pkg); registry != nil {
			writeFile(filepath.Join(directory, registryFile), registry)
		}
	}
	if pkg.Name == "main" {
		writeFile(filepath.Join(directory, wiringFile), mainWiring(config.Plugins))
	}
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
	sourceRoot, targetRoot := absolutePath(*source), absolutePath(*target)
	if _, err := os.Stat(targetRoot); !errors.Is(err, fs.ErrNotExist) {
		log.Fatalf("the target %s exists; fprewrite writes a fresh copy", targetRoot)
	}
	if strings.HasPrefix(targetRoot, sourceRoot+string(filepath.Separator)) {
		log.Fatalf("the target %s lies inside the source %s", targetRoot, sourceRoot)
	}
	if err := copyTree(sourceRoot, targetRoot); err != nil {
		log.Fatal(err)
	}
	manifest := Manifest{Service: *service, Language: "go", Points: []PointEntry{}}
	for _, pkg := range loadPackages(sourceRoot) {
		manifest.Points = append(manifest.Points, instrumentPackage(*service, sourceRoot, targetRoot, config, pkg)...)
	}
	if err := requireSDK(targetRoot, absolutePath(*sdk)); err != nil {
		log.Fatal(err)
	}
	tidy := exec.Command("go", "mod", "tidy")
	tidy.Dir, tidy.Stdout, tidy.Stderr = targetRoot, os.Stderr, os.Stderr
	if err := tidy.Run(); err != nil {
		log.Fatalf("go mod tidy in the copy: %v", err)
	}
	writeManifest(filepath.Join(targetRoot, manifestFile), manifest)
	fmt.Printf("%d points placed in %s\n", len(manifest.Points), targetRoot)
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
	sourceRoot := absolutePath(*source)
	manifest := Manifest{Service: *service, Language: "go", Points: []PointEntry{}}
	for _, pkg := range loadPackages(sourceRoot) {
		for _, file := range pkg.Syntax {
			relative := relativePath(sourceRoot, pkg.Fset.Position(file.Pos()).Filename)
			manifest.Points = append(manifest.Points, placePoints(*service, relative, config, pkg, file)...)
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
