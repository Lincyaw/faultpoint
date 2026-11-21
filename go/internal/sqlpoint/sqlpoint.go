// Package sqlpoint classifies SQL statements into the store points of the SQL adapter plugins, holds how drivers build
// the errors their fail rules inject and describes their failures.
package sqlpoint

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	"faultpoint"

	"github.com/DataDog/go-sqllexer"
)

// hashDigits is how many hexadecimal digits of a statement's hash its locator ends with.
const hashDigits = 8

// StatementLocator matches the locators Classify gives the points of statements, which the SQL adapter plugins
// serve.
var StatementLocator = regexp.MustCompile("#[0-9a-f]{" + strconv.Itoa(hashDigits) + "}$")

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

// clauseCommands are the words go-sqllexer lexes as commands that are clauses of a statement, the joins of a SELECT.
var clauseCommands = []string{"JOIN", "STRAIGHT_JOIN"}

// Classifier classifies statements, a statement being a read when it only reads, as reads tells.
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
	point := Point{Kind: "store_write", Command: "-"}
	if c.reads(query) {
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
	point.Locator = tables + "#" + hex.EncodeToString(digest[:])[:hashDigits]
	c.points.Store(query, point)
	return point
}

// reads is whether a statement only reads: it runs a command, each a read command, and writes no table with INTO, as
// SELECT ... INTO does. A join, and the UPDATE of a FOR UPDATE, FOR NO KEY UPDATE or ON DUPLICATE KEY UPDATE clause,
// which go-sqllexer lexes as commands too, are clauses of their statement, not commands.
func (c *Classifier) reads(query string) bool {
	lexer := sqllexer.New(query)
	previous := ""
	commands := 0
	for token := lexer.Scan(); token.Type != sqllexer.EOF; token = lexer.Scan() {
		word := strings.ToUpper(token.Value)
		command := token.Type == sqllexer.COMMAND && !slices.Contains(clauseCommands, word) &&
			(word != "UPDATE" || (previous != "FOR" && previous != "KEY"))
		switch {
		case token.Type == sqllexer.KEYWORD && word == "INTO":
			return false
		case command && !slices.ContainsFunc(c.readCommands, func(read string) bool { return strings.EqualFold(read, word) }):
			return false
		case command:
			commands++
		}
		if token.Type != sqllexer.SPACE && token.Type != sqllexer.COMMENT && token.Type != sqllexer.MULTILINE_COMMENT {
			previous = word
		}
	}
	return commands > 0
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
