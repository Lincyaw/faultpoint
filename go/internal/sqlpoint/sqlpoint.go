// Package sqlpoint classifies SQL statements into the store points of the SQL adapter plugins, holds how drivers build
// the errors their fail rules inject and describes their failures.
package sqlpoint

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strconv"
	"strings"
	"sync"

	"faultpoint"

	"github.com/DataDog/go-sqllexer"
)

// CodedErrors build, by the package of a database/sql driver, the error the driver returns for a statement refused
// with a code; the adapter plugin of the driver's client library adds its builder from its init, so that the SQL
// adapter depends on no driver.
var CodedErrors = map[string]func(code string) error{}

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

// ErrorDetail is the detail of a failed statement: the error's name and, when the driver reports one, its code: the
// SQLSTATE of a PostgreSQL driver, or the numeric code of a driver such as SQLite's.
func ErrorDetail(err error) map[string]string {
	detail := map[string]string{"error": faultpoint.ErrorName(err)}
	var state interface{ SQLState() string }
	var numbered interface{ Code() int }
	switch {
	case errors.As(err, &state):
		detail["code"] = state.SQLState()
	case errors.As(err, &numbered):
		detail["code"] = strconv.Itoa(numbered.Code())
	}
	return detail
}
