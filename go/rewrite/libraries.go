package main

import (
	"log"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/tools/go/packages"
)

const librariesDir = "faultpoint-libraries"

// alwaysExcluded are the paths that never get points: the SDK itself, and OpenTelemetry and the logging libraries
// it observes through, so that points do not change the observation itself.
var alwaysExcluded = []string{"faultpoint", "go.opentelemetry.io", "go.uber.org/zap", "github.com/sirupsen/logrus",
	"github.com/rs/zerolog", "k8s.io/klog"}

// under is whether a package path is a path or lies below it.
func under(pkgPath, path string) bool {
	return pkgPath == path || strings.HasPrefix(pkgPath, path+"/")
}

// scopedLibraries are the dependency packages of an import graph that the placement's scope names, with the entry
// that names them; the standard library, the local modules and the excluded paths get no points.
func scopedLibraries(graph []*packages.Package, placement Placement) map[string]ScopeEntry {
	excluded := append(slices.Clone(alwaysExcluded), placement.Exclude...)
	libraries := map[string]ScopeEntry{}
	for _, pkg := range graph {
		if pkg.Module == nil || local(pkg.Module) || slices.ContainsFunc(excluded, func(path string) bool { return under(pkg.PkgPath, path) }) {
			continue
		}
		index := slices.IndexFunc(placement.Scope, func(entry ScopeEntry) bool { return under(pkg.PkgPath, entry.Include) })
		if index >= 0 {
			libraries[pkg.PkgPath] = placement.Scope[index]
		}
	}
	return libraries
}

// versionedPrefix is how the points of a dependency module are identified: its path and the version the build
// uses, so that an upgraded dependency does not reuse the ids of the old one.
func versionedPrefix(found *packages.Module) string {
	version := found.Version
	if found.Replace != nil {
		version = found.Replace.Version
	}
	return found.Path + "@" + version + "/"
}

// libraryCopies are the copies of the dependency modules that hold packages in scope. Go builds no overlay of a file
// in the module cache, so each such module is copied once beside the service and replaced by its copy, while the
// module cache stays untouched.
type libraryCopies struct {
	dir     string
	modules map[string]string
}

// of is the directory of the copy of a dependency module, made on first use.
func (l *libraryCopies) of(found *packages.Module) string {
	dir, copied := l.modules[found.Path]
	if !copied {
		dir = filepath.Join(l.dir, filepath.FromSlash(strings.TrimSuffix(versionedPrefix(found), "/")))
		if err := copyTree(found.Dir, dir); err != nil {
			log.Fatal(err)
		}
		l.modules[found.Path] = dir
	}
	return dir
}

// instrumentLibrary places the points of a dependency package as far as its scope entry allows, writes its rewritten
// files and its error registry into the copy of its module, and returns the points.
func instrumentLibrary(service string, placement Placement, entry ScopeEntry, copies *libraryCopies, pkg *packages.Package) []PointEntry {
	limited := placement.limitedTo(entry.Kinds)
	prefix := versionedPrefix(pkg.Module)
	var placed []PointEntry
	for _, file := range pkg.Syntax {
		relative := relativePath(pkg.Module.Dir, pkg.Fset.Position(file.Pos()).Filename)
		points := placePoints(service, prefix+relative, limited, pkg, file)
		if len(points) > 0 {
			writeFile(filepath.Join(copies.of(pkg.Module), relative), rewriteFile(pkg, file, []string{pointsPackage}))
			placed = append(placed, points...)
		}
	}
	if registry := errorRegistry(pkg); registry != nil && limited.Errors {
		directory := relativePath(pkg.Module.Dir, filepath.Dir(pkg.GoFiles[0]))
		writeFile(filepath.Join(copies.of(pkg.Module), directory, registryFile), registry)
	}
	return placed
}

// copyLibraries instruments the dependency packages in scope as the copy of the service resolves them, and returns
// their points and the copies that replace their modules.
func copyLibraries(service string, placement Placement, libraries map[string]ScopeEntry, copied, target string) ([]PointEntry, map[string]string) {
	copies := &libraryCopies{dir: filepath.Join(target, librariesDir), modules: map[string]string{}}
	var placed []PointEntry
	for _, pkg := range loadPackages(copied, slices.Sorted(maps.Keys(libraries))...) {
		placed = append(placed, instrumentLibrary(service, placement, libraries[pkg.PkgPath], copies, pkg)...)
	}
	return placed, copies.modules
}

// scanLibraries lists the points of the dependency packages in scope without writing anything, as instrumentLibrary
// places them.
func scanLibraries(service, dir string, placement Placement, libraries map[string]ScopeEntry) []PointEntry {
	var placed []PointEntry
	for _, pkg := range loadPackages(dir, slices.Sorted(maps.Keys(libraries))...) {
		limited := placement.limitedTo(libraries[pkg.PkgPath].Kinds)
		for _, file := range pkg.Syntax {
			relative := relativePath(pkg.Module.Dir, pkg.Fset.Position(file.Pos()).Filename)
			placed = append(placed, placePoints(service, versionedPrefix(pkg.Module)+relative, limited, pkg, file)...)
		}
	}
	return placed
}
