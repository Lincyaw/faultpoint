// Package fpredis is the adapter plugin of go-redis: a hook on the clients the rewriter wires makes every command
// of the command table in its options a store_read, store_write, publish or consume point.
package fpredis

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"

	"faultpoint"
	"faultpoint/fpaction"

	"github.com/redis/go-redis/v9"
)

// command is where a command is a point: its kind, and the argument after which its key comes, when not first.
type command struct {
	Kind     string `json:"kind"`
	KeyAfter string `json:"key_after"`
}

const defaultIdentifier = `[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|\b[0-9a-fA-F]{16,}\b|\b\d+\b`

var (
	read            = command{Kind: "store_read"}
	write           = command{Kind: "store_write"}
	publish         = command{Kind: "publish"}
	consume         = command{Kind: "consume"}
	consumeStreams  = command{Kind: "consume", KeyAfter: "streams"}
	defaultCommands = map[string]command{
		"get": read, "hget": read, "hgetall": read, "exists": read, "smembers": read, "sismember": read, "scard": read,
		"lrange": read, "llen": read, "zrange": read, "zrangebyscore": read, "zscore": read, "zcard": read,
		"xrange": read, "xrevrange": read, "xlen": read, "xpending": read,
		"set": write, "setnx": write, "setex": write, "psetex": write, "getset": write, "getdel": write, "del": write,
		"unlink": write, "expire": write, "pexpire": write, "persist": write, "hset": write, "hsetnx": write,
		"hdel": write, "hincrby": write, "incr": write, "incrby": write, "decr": write, "decrby": write, "sadd": write,
		"srem": write, "lpush": write, "rpush": write, "lpop": write, "rpop": write, "lrem": write, "ltrim": write,
		"zadd": write, "zrem": write, "zincrby": write, "xack": write, "xdel": write, "xtrim": write,
		"xadd": publish, "publish": publish,
		"xreadgroup": consumeStreams, "xread": consumeStreams, "xautoclaim": consume, "xclaim": consume,
	}
)

var (
	enabled    bool
	commands   map[string]command
	identifier *regexp.Regexp
)

func init() {
	options := struct {
		Commands   map[string]command `json:"commands"`
		Identifier string             `json:"identifier"`
	}{Commands: defaultCommands, Identifier: defaultIdentifier}
	enabled = faultpoint.Register(faultpoint.Plugin{Name: "redis", Options: &options, Actions: map[string][]string{
		"store_read":  {"fail", "empty", "delay", "crash"},
		"store_write": {"fail", "fail_after", "drop", "duplicate", "delay", "crash"},
		"publish":     {"fail", "fail_after", "drop", "duplicate", "delay", "crash"},
		"consume":     {"fail", "fail_after", "delay", "crash"},
	}})
	pattern, err := regexp.Compile(options.Identifier)
	if err != nil {
		faultpoint.Abort("option identifier of redis: %v", err)
	}
	commands, identifier = options.Commands, pattern
}

// Instrument adds the hook to a client and returns it; the client of a plugin that is not enabled is returned as
// it is.
func Instrument[C interface{ AddHook(redis.Hook) }](client C) C {
	if enabled {
		client.AddHook(hook{})
	}
	return client
}

// call is one execution of a command at its point.
type call struct {
	ctx    context.Context
	point  string
	kind   string
	rule   *faultpoint.Rule
	action string
}

// decide finds a command in the table, decides its rule and performs the rule's delay or crash; a command outside
// the table is not a point.
func decide(ctx context.Context, cmd redis.Cmder) (call, bool) {
	known, found := commands[cmd.Name()]
	if !found {
		return call{}, false
	}
	arguments := cmd.Args()
	key := "-"
	for index := 1; index < len(arguments); index++ {
		if known.KeyAfter == "" || strings.EqualFold(fmt.Sprint(arguments[index-1]), known.KeyAfter) {
			key = identifier.ReplaceAllString(fmt.Sprint(arguments[index]), "{}")
			break
		}
	}
	c := call{ctx: ctx, kind: known.Kind,
		point: faultpoint.PointID(faultpoint.Service(), known.Kind, strings.ToUpper(cmd.Name())+" "+key)}
	c.rule = faultpoint.Decide(ctx, c.point)
	if c.rule != nil {
		fpaction.Hold(c.rule)
		c.action = c.rule.Action.Kind
	}
	return c, true
}

// sent is whether the command reaches Redis: a fail or drop rule keeps it back.
func (c call) sent() bool { return c.action != "fail" && c.action != "drop" }

// settle applies what a rule does once the command was sent or kept back, and observes the outcome.
func (c call) settle(cmd redis.Cmder, err error) error {
	if c.action == "fail" || (err == nil && c.action == "fail_after") {
		err = fpaction.Failure(c.rule)
	}
	if err == nil && c.action == "empty" {
		err = emptied(cmd)
	}
	if err != nil {
		cmd.SetErr(err)
	}
	outcome, total := "ok", 0
	switch {
	case c.kind == "consume" && errors.Is(err, redis.Nil):
	case c.kind == "store_read" && errors.Is(err, redis.Nil):
		outcome = "empty"
	case err != nil:
		outcome = "error"
	case c.kind == "store_read" && size(cmd) > 0:
		outcome, total = "rows", size(cmd)
	case c.kind == "store_read":
		outcome = "empty"
	}
	faultpoint.Observe(c.ctx, c.point, outcome, float64(total), c.rule)
	return err
}

// Every typed go-redis command has Val and SetVal, which emptied and size read through reflection.

// emptied makes a read a miss: redis.Nil for a single string or number lookup, the empty value of anything else.
func emptied(cmd redis.Cmder) error {
	value := reflect.ValueOf(cmd).MethodByName("Val").Call(nil)[0]
	switch value.Kind() {
	case reflect.String, reflect.Float32, reflect.Float64:
		return redis.Nil
	case reflect.Slice:
		value = reflect.MakeSlice(value.Type(), 0, 0)
	case reflect.Map:
		value = reflect.MakeMap(value.Type())
	default:
		value = reflect.Zero(value.Type())
	}
	reflect.ValueOf(cmd).MethodByName("SetVal").Call([]reflect.Value{value})
	return nil
}

// size is how many values a read returned: the length of a collection, else 1 for a value that is not zero.
func size(cmd redis.Cmder) int {
	value := reflect.ValueOf(cmd).MethodByName("Val").Call(nil)[0]
	switch {
	case value.Kind() == reflect.Slice || value.Kind() == reflect.Map:
		return value.Len()
	case value.IsZero():
		return 0
	}
	return 1
}

type hook struct{}

func (hook) DialHook(next redis.DialHook) redis.DialHook { return next }

func (hook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		c, known := decide(ctx, cmd)
		if !known {
			return next(ctx, cmd)
		}
		var err error
		if c.sent() {
			err = next(ctx, cmd)
		}
		if err == nil && c.action == "duplicate" {
			err = next(ctx, cmd)
		}
		return c.settle(cmd, err)
	}
}

// ProcessPipelineHook sends the commands no rule keeps back in one round trip, as the caller asked; a duplicate
// would leave the pipeline or its transaction, so a pipeline cannot duplicate.
func (hook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
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
		var err error
		if len(sent) > 0 {
			err = next(ctx, sent)
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
