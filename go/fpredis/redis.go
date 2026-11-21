// Package fpredis is the adapter plugin of go-redis: a hook on the clients the rewriter wires makes every command of
// the shared command table spec/redis-commands.json a store_read, store_write, publish or consume point.
package fpredis

//go:generate cp ../../spec/redis-commands.json commands.json

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"faultpoint"
	"faultpoint/internal/action"

	"github.com/redis/go-redis/v9"
)

//go:embed commands.json
var table []byte

// command is where a command of the table is a point: its kind, where its key is among the arguments after the
// command name, and which reply of a read or consume is empty.
type command struct {
	Kind  string          `json:"kind"`
	Key   json.RawMessage `json:"key"`
	Empty string          `json:"empty"`
}

var (
	enabled    bool
	commands   map[string]command
	identifier *regexp.Regexp
)

func init() {
	var options struct {
		Commands      map[string]command `json:"commands"`
		KeyIdentifier string             `json:"key_identifier"`
	}
	if err := json.Unmarshal(table, &options); err != nil {
		faultpoint.Abort("the redis command table: %v", err)
	}
	enabled = faultpoint.Register(faultpoint.Plugin{Name: "redis", Options: &options, Serves: commandLocator,
		Actions: map[string][]string{
			"store_read":  {"fail", "empty", "delay", "crash"},
			"consume":     {"fail", "fail_after", "empty", "delay", "crash"},
			"store_write": {"fail", "fail_after", "drop", "duplicate", "delay", "crash"},
			"publish":     {"fail", "fail_after", "drop", "duplicate", "delay", "crash"},
		}})
	pattern, err := regexp.Compile(options.KeyIdentifier)
	if err != nil {
		faultpoint.Abort("option key_identifier of redis: %v", err)
	}
	commands, identifier = options.Commands, pattern
}

// commandLocator is whether a locator starts with a command of the table, as those of the plugin's points do.
func commandLocator(locator string) bool {
	name, _, _ := strings.Cut(locator, " ")
	_, known := commands[name]
	return known
}

// Instrument adds the hook to a client and returns it; the client of a plugin that is not enabled is returned as
// it is.
func Instrument[C interface{ AddHook(redis.Hook) }](client C) C {
	defer faultpoint.Guard()
	if enabled {
		client.AddHook(hook{})
	}
	return client
}

// key is the key of a command by the table's key position: an index among the arguments after the command name,
// "after:TOKEN" for the argument after that token, "numkeys:N" for the first key after the key count at N, or null.
func key(position json.RawMessage, arguments []any) (string, bool) {
	var index int
	var text string
	switch {
	case json.Unmarshal(position, &index) == nil && index+1 < len(arguments):
		return fmt.Sprint(arguments[index+1]), true
	case json.Unmarshal(position, &text) != nil || text == "":
		return "", false
	case strings.HasPrefix(text, "after:"):
		for at := 1; at+1 < len(arguments); at++ {
			if strings.EqualFold(fmt.Sprint(arguments[at]), strings.TrimPrefix(text, "after:")) {
				return fmt.Sprint(arguments[at+1]), true
			}
		}
	case strings.HasPrefix(text, "numkeys:"):
		at, err := strconv.Atoi(strings.TrimPrefix(text, "numkeys:"))
		if err == nil && at+2 < len(arguments) && fmt.Sprint(arguments[at+1]) != "0" {
			return fmt.Sprint(arguments[at+2]), true
		}
	}
	return "", false
}

// call is one execution of a command at its point.
type call struct {
	ctx     context.Context
	point   string
	command command
	rule    *faultpoint.Rule
	action  string
	started time.Time
}

// decide finds a command in the table, decides its rule that acts before it is sent and performs the rule's delay or
// crash; a command outside the table is not a point.
func decide(ctx context.Context, cmd redis.Cmder) (call, bool) {
	defer faultpoint.Guard()
	started := time.Now()
	name := strings.ToUpper(cmd.Name())
	known, found := commands[name]
	if !found {
		return call{}, false
	}
	locator := name
	if found, exists := key(known.Key, cmd.Args()); exists {
		locator += " " + identifier.ReplaceAllString(found, "{}")
	}
	c := call{ctx: ctx, command: known, point: faultpoint.PointID(faultpoint.Service(), known.Kind, locator),
		started: started}
	c.rule = faultpoint.Decide(ctx, c.point, action.Before...)
	if c.rule != nil {
		action.Hold(c.rule)
		c.action = c.rule.Action.Kind
	}
	if c.action == "empty" && known.Empty == "never" {
		faultpoint.Abort("rule %s: %s has no empty reply", c.rule.ID, c.point)
	}
	return c, true
}

// sent is whether the command reaches Redis: fail and drop keep it back, and so does empty, except for an
// array of nils, whose length only the reply knows.
func (c call) sent() bool {
	return c.action != "fail" && c.action != "drop" && (c.action != "empty" || c.command.Empty == "all_nil")
}

// block waits as long as a blocking read kept back by an empty rule would have waited for its empty reply, so that
// a consumer loop does not spin.
func (c call) block(cmd redis.Cmder) {
	arguments := cmd.Args()
	for index := 1; index+1 < len(arguments) && c.action == "empty"; index++ {
		milliseconds, err := strconv.Atoi(fmt.Sprint(arguments[index+1]))
		if strings.EqualFold(fmt.Sprint(arguments[index]), "block") && err == nil {
			select {
			case <-time.After(time.Duration(milliseconds) * time.Millisecond):
			case <-c.ctx.Done():
			}
			return
		}
	}
}

// settle applies what a rule does once the command was sent or kept back, and observes the outcome; a fail_after
// rule is decided only for a command that no rule acted on before and that completed normally: answered without an
// error reply, or, for a read, with the empty reply redis.Nil stands for.
func (c call) settle(cmd redis.Cmder, err error) error {
	defer faultpoint.Guard()
	reads := c.command.Kind == "store_read" || c.command.Kind == "consume"
	if (err == nil || (reads && c.command.Empty == "nil" && errors.Is(err, redis.Nil))) && c.rule == nil {
		c.rule = faultpoint.Decide(c.ctx, c.point, "fail_after")
	}
	if c.rule != nil {
		c.action = c.rule.Action.Kind
	}
	switch {
	case c.action == "fail" || c.action == "fail_after":
		err = action.Failure(c.rule, replyError)
	case err == nil && c.action == "empty":
		err = emptied(cmd, c.command.Empty)
	}
	if err != nil {
		cmd.SetErr(err)
	}
	outcome, total := "ok", 0
	var detail map[string]string
	switch {
	case reads && c.command.Empty == "nil" && errors.Is(err, redis.Nil):
		outcome = "empty"
	case err != nil:
		outcome, detail = "error", errorDetail(err)
	case reads && empty(cmd, c.command.Empty):
		outcome = "empty"
	case reads:
		outcome, total = "rows", size(cmd)
	}
	faultpoint.Observe(c.ctx, c.point, outcome, float64(total), faultpoint.Elapsed(c.started), c.rule, detail)
	return err
}

// replyType is the type go-redis gives an error reply of Redis, proto.RedisError, which is internal to go-redis;
// redis.Nil is its one exported value.
var replyType = reflect.TypeOf(redis.Nil)

// replyError is the error go-redis gives for an error reply that starts with code, as a fail rule injects it.
func replyError(code string) error {
	return reflect.ValueOf(code + " " + action.ErrInjected.Error()).Convert(replyType).Interface().(error)
}

// errorDetail is the detail of a failed command: the error's name and, for an error reply of Redis, its prefix,
// such as WRONGTYPE or NOSCRIPT.
func errorDetail(err error) map[string]string {
	detail := map[string]string{"error": faultpoint.ErrorName(err)}
	var reply redis.Error
	if errors.As(err, &reply) {
		detail["code"], _, _ = strings.Cut(reply.Error(), " ")
	}
	return detail
}

// Every typed go-redis command has Val and SetVal, through which the reply is read and replaced.
func reply(cmd redis.Cmder) reflect.Value {
	return reflect.ValueOf(cmd).MethodByName("Val").Call(nil)[0]
}

// emptied gives a command the empty reply of the table: redis.Nil, an empty array or map, an empty string, zero, or
// its own reply with every element nil.
func emptied(cmd redis.Cmder, kind string) error {
	if kind == "nil" {
		return redis.Nil
	}
	value := reply(cmd)
	replaced := reflect.Zero(value.Type())
	switch {
	case kind == "all_nil":
		replaced = reflect.MakeSlice(value.Type(), value.Len(), value.Len())
	case value.Kind() == reflect.Slice:
		replaced = reflect.MakeSlice(value.Type(), 0, 0)
	case value.Kind() == reflect.Map:
		replaced = reflect.MakeMap(value.Type())
	}
	reflect.ValueOf(cmd).MethodByName("SetVal").Call([]reflect.Value{replaced})
	return nil
}

// empty is whether a reply is the empty reply of the table.
func empty(cmd redis.Cmder, kind string) bool {
	value := reply(cmd)
	switch kind {
	case "empty_array":
		return value.Len() == 0
	case "empty_string", "zero":
		return value.IsZero()
	case "all_nil":
		for index := range value.Len() {
			if !value.Index(index).IsNil() {
				return false
			}
		}
		return true
	}
	return false
}

// size is how many values a read returned: the length of a collection, else 1.
func size(cmd redis.Cmder) int {
	value := reply(cmd)
	if value.Kind() == reflect.Slice || value.Kind() == reflect.Map {
		return value.Len()
	}
	return 1
}

type hook struct{}

func (hook) DialHook(next redis.DialHook) redis.DialHook { return next }

func (hook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) (err error) {
		defer faultpoint.Guard()
		c, known := decide(ctx, cmd)
		if !known {
			faultpoint.Outside(func() { err = next(ctx, cmd) })
			return err
		}
		if c.sent() {
			faultpoint.Outside(func() { err = next(ctx, cmd) })
		} else {
			c.block(cmd)
		}
		if err == nil && c.action == "duplicate" {
			faultpoint.Outside(func() { err = next(ctx, cmd) })
		}
		return c.settle(cmd, err)
	}
}

// ProcessPipelineHook sends the commands no rule keeps back in one round trip, as the caller asked; a duplicate
// would leave the pipeline or its transaction, so a pipeline cannot duplicate.
func (hook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) (err error) {
		defer faultpoint.Guard()
		calls := make([]call, len(cmds))
		known := make([]bool, len(cmds))
		sent := make([]redis.Cmder, 0, len(cmds))
		for index, cmd := range cmds {
			calls[index], known[index] = decide(ctx, cmd)
			if known[index] && calls[index].action == "duplicate" {
				faultpoint.Abort("rule %s: a pipeline cannot duplicate %s", calls[index].rule.ID, calls[index].point)
			}
			if !known[index] || calls[index].sent() {
				sent = append(sent, cmd)
			}
		}
		if len(sent) > 0 {
			faultpoint.Outside(func() { err = next(ctx, sent) })
		}
		for index, cmd := range cmds {
			if known[index] {
				calls[index].settle(cmd, cmd.Err())
			}
		}
		for _, cmd := range cmds {
			if err == nil && cmd.Err() != nil {
				err = cmd.Err()
			}
		}
		return err
	}
}
