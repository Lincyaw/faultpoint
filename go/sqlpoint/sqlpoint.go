// Package sqlpoint classifies SQL statements into the store points of the SQL adapter plugins.
package sqlpoint

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
	"sync"

	"faultpoint"

	"github.com/DataDog/go-sqllexer"
)

// Point is where a statement is a store point: its kind, its locator, and its first command, upper case.
type Point struct {
	Kind    string
	Locator string
	Command string
}

// Classifier classifies statements, a statement being a read when all its commands are read commands.
type Classifier struct {
	readCommands []string
	points       sync.Map
	obfuscator   *sqllexer.Obfuscator
	normalizer   *sqllexer.Normalizer
}

// NewClassifier classifies by the read commands of a plugin's options.
func NewClassifier(readCommands []string) *Classifier {
	return &Classifier{readCommands: readCommands, obfuscator: sqllexer.NewObfuscator(),
		normalizer: sqllexer.NewNormalizer(sqllexer.WithCollectTables(true), sqllexer.WithCollectCommands(true))}
}

// Classify is the point of a statement; its locator is the tables it touches and the hash of its shape with
// literals and comments removed, so that one statement is one point whatever its arguments.
func (c *Classifier) Classify(query string) Point {
	if known, found := c.points.Load(query); found {
		return known.(Point)
	}
	shape, metadata, err := sqllexer.ObfuscateAndNormalize(query, c.obfuscator, c.normalizer)
	if err != nil {
		faultpoint.Abort("cannot normalize a statement: %v", err)
	}
	reads := len(metadata.Commands) > 0 && !slices.ContainsFunc(metadata.Commands, func(command string) bool {
		return !slices.ContainsFunc(c.readCommands, func(read string) bool { return strings.EqualFold(read, command) })
	})
	point := Point{Kind: "store_write", Command: "-"}
	if reads {
		point.Kind = "store_read"
	}
	if len(metadata.Commands) > 0 {
		point.Command = strings.ToUpper(metadata.Commands[0])
	}
	tables := strings.Join(slices.Sorted(slices.Values(metadata.Tables)), "+")
	if tables == "" {
		tables = "-"
	}
	digest := sha256.Sum256([]byte(shape))
	point.Locator = tables + "#" + hex.EncodeToString(digest[:])[:8]
	c.points.Store(query, point)
	return point
}
