package main

import (
	"errors"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/semver"
	"golang.org/x/tools/go/packages"
)

// module is a Go module the rewriter instruments; a point in a module other than the service's own is identified by
// the module path, since its files lie outside the service.
type module struct {
	dir    string
	prefix string
}

// localModules are the source module and the local modules its packages import: the modules of the go.work that
// governs the source, and modules replaced by directories, as the go command resolves them.
func localModules(source string) []module {
	config := &packages.Config{Dir: source, Mode: packages.NeedName | packages.NeedModule | packages.NeedImports | packages.NeedDeps}
	loaded, err := packages.Load(config, "./...")
	if err != nil {
		log.Fatal(err)
	}
	if packages.PrintErrors(loaded) > 0 {
		os.Exit(1)
	}
	modules := []module{{dir: source}}
	packages.Visit(loaded, nil, func(pkg *packages.Package) {
		found := pkg.Module
		if found == nil || found.Dir == "" || (!found.Main && (found.Replace == nil || found.Replace.Version != "")) {
			return
		}
		if !slices.ContainsFunc(modules, func(known module) bool { return known.dir == found.Dir }) {
			modules = append(modules, module{dir: found.Dir, prefix: found.Path + "/"})
		}
	})
	return modules
}

// workspaceFile is the go.work that governs a directory, or empty when none does.
func workspaceFile(dir string) string {
	command := exec.Command("go", "env", "GOWORK")
	command.Dir = dir
	output, err := command.Output()
	if err != nil {
		log.Fatal(err)
	}
	path := strings.TrimSpace(string(output))
	if path == "off" {
		return ""
	}
	return path
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

// requireSDK makes a copied module require the SDK from its local path and tidies it, for a copy without go.work.
func requireSDK(copied, sdk string) {
	path := filepath.Join(copied, "go.mod")
	content, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	parsed, err := modfile.Parse(path, content, nil)
	if err != nil {
		log.Fatal(err)
	}
	if err := parsed.AddRequire(corePackage, "v0.0.0"); err != nil {
		log.Fatal(err)
	}
	if err := parsed.AddReplace(corePackage, "", sdk, ""); err != nil {
		log.Fatal(err)
	}
	formatted, err := parsed.Format()
	if err != nil {
		log.Fatal(err)
	}
	writeFile(path, formatted)
	tidy := exec.Command("go", "mod", "tidy")
	tidy.Dir, tidy.Env, tidy.Stdout, tidy.Stderr = copied, append(os.Environ(), "GOWORK=off"), os.Stderr, os.Stderr
	if err := tidy.Run(); err != nil {
		log.Fatalf("go mod tidy in %s: %v", copied, err)
	}
}

// writeWorkspace writes the go.work of a copy: the original's directives, with the copied modules and the SDK as
// its modules, so that the copy builds as the source does and the SDK's requirements come from its own go.mod.
func writeWorkspace(original, target string, copies []string, sdk string) {
	content, err := os.ReadFile(original)
	if err != nil {
		log.Fatal(err)
	}
	work, err := modfile.ParseWork(original, content, nil)
	if err != nil {
		log.Fatal(err)
	}
	for _, used := range slices.Clone(work.Use) {
		if err := work.DropUse(used.Path); err != nil {
			log.Fatal(err)
		}
	}
	for _, replaced := range slices.Clone(work.Replace) {
		if replaced.New.Version == "" {
			if err := work.DropReplace(replaced.Old.Path, replaced.Old.Version); err != nil {
				log.Fatal(err)
			}
		}
	}
	for _, copied := range copies {
		if err := work.AddUse("./"+relativePath(target, copied), ""); err != nil {
			log.Fatal(err)
		}
	}
	if err := work.AddUse(sdk, ""); err != nil {
		log.Fatal(err)
	}
	if sdkGo := goVersion(filepath.Join(sdk, "go.mod")); work.Go == nil || semver.Compare("v"+work.Go.Version, "v"+sdkGo) < 0 {
		if err := work.AddGoStmt(sdkGo); err != nil {
			log.Fatal(err)
		}
	}
	work.Cleanup()
	writeFile(filepath.Join(target, "go.work"), modfile.Format(work.Syntax))
	sums, err := os.ReadFile(original + ".sum")
	switch {
	case err == nil:
		writeFile(filepath.Join(target, "go.work.sum"), sums)
	case !errors.Is(err, fs.ErrNotExist):
		log.Fatal(err)
	}
}

func goVersion(path string) string {
	content, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	parsed, err := modfile.Parse(path, content, nil)
	if err != nil {
		log.Fatal(err)
	}
	return parsed.Go.Version
}
