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
	"net"
	"os"
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
	if !enabled {
		return client
	}
	instrumented := hook{}
	if single, isSingle := any(client).(*redis.Client); isSingle {
		instrumented.readTimeout = single.Options().ReadTimeout
		instrumented.server = serverAddress(single.Options().Addr)
		instrumented.once = single.Options().MaxRetries == 0
	}
	client.AddHook(instrumented)
	return client
}

// serverAddress is the TCP address of a Redis server as a read error names it.
type serverAddress string

func (a serverAddress) Network() string { return "tcp" }
func (a serverAddress) String() string  { return string(a) }

// wait holds a command as its rule says, as a slow server holds its reply: a caller that gives up ends the wait with
// its context's error, and, but for a consume, whose read the command's own block bounds, a wait longer than the
// client's read timeout fails once the timeout is over with the error of a timed-out read.
func (h hook) wait(ctx context.Context, rule *faultpoint.Rule, kind string) error {
	pause := action.Pause(rule)
	if h.readTimeout <= 0 || kind == "consume" || pause <= h.readTimeout {
		return action.Sleep(ctx, pause)
	}
	if err := action.Sleep(ctx, h.readTimeout); err != nil {
		return err
	}
	return &net.OpError{Op: "read", Net: "tcp", Addr: h.server, Err: os.ErrDeadlineExceeded}
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
	// ended is the context's error when the caller gave up during the rule's wait.
	ended error
	// once is whether the client sends a command at most once, as hook.once tells.
	once bool
}

// decide finds a command in the table, decides its rule that acts before it is sent and performs the rule's wait or
// crash; a command outside the table is not a point.
func (h hook) decide(ctx context.Context, cmd redis.Cmder) (call, bool) {
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
		started: started, once: h.once}
	c.rule = faultpoint.Decide(ctx, c.point, action.Before...)
	if c.rule != nil {
		c.ended = h.wait(ctx, c.rule, known.Kind)
		c.action = c.rule.Action.Kind
	}
	if c.action == "empty" && known.Empty == "never" {
		faultpoint.Abort("rule %s: %s has no empty reply", c.rule.ID, c.point)
	}
	return c, true
}

// sent is whether the command reaches Redis: a caller that gave up during the wait, fail and drop keep it back, and
// so does empty, except for an array of nils, whose length only the reply knows.
func (c call) sent() bool {
	return c.ended == nil && c.action != "fail" && c.action != "drop" &&
		(c.action != "empty" || c.command.Empty == "all_nil")
}

// late is whether the command still reaches Redis after its caller gave up: a delay the caller's timeout or
// cancellation cut short models a slow server, which still runs it, while a fail's wait cut short sends nothing.
func (c call) late() bool { return c.ended != nil && c.action == "delay" }

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
	case c.ended != nil:
		err = c.ended
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
		outcome, detail = "error", action.Sent(errorDetail(err), c.rule, c.ended != nil, err, c.reached)
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

// reached tells whether a command that go-redis failed reached Redis: a reply, or a failure reading one, says it did.
// For a client that sends a command once, a failure to take or set up a connection or to write the command says it
// did not, while after a retry, which may have sent it before, it tells nothing; nor does any other failure.
func (c call) reached(err error) (sent, known bool) {
	var reply redis.Error
	var failed *net.OpError
	var timeout net.Error
	operation := errors.As(err, &failed)
	switch {
	case errors.As(err, &reply), operation && failed.Op == "read":
		return true, true
	case !c.once:
		return false, false
	// go-redis unwraps the error of setting up a connection, so a timeout there, like the pool's, is no
	// *net.OpError; a bare context error is the end of a wait for the pool.
	case operation && (failed.Op == "dial" || failed.Op == "write"), errors.Is(err, redis.ErrClosed),
		err == context.Canceled, err == context.DeadlineExceeded, !operation && errors.As(err, &timeout) && timeout.Timeout():
		return false, true
	}
	return false, false
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

// hook makes the commands of one client points, with the read timeout and the server of a single client, which are
// zero for other clients, whose injected waits only their callers end; once is whether the client is a single one
// that does not retry, whose failure before sending a command shows that it never sent it.
type hook struct {
	readTimeout time.Duration
	server      serverAddress
	once        bool
}

func (hook) DialHook(next redis.DialHook) redis.DialHook { return next }

func (h hook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) (err error) {
		defer faultpoint.Guard()
		c, known := h.decide(ctx, cmd)
		if !known {
			faultpoint.Outside(func() { err = next(ctx, cmd) })
			return err
		}
		if c.sent() {
			faultpoint.Outside(func() { err = next(ctx, cmd) })
		} else {
			c.block(cmd)
		}
		if c.late() {
			action.SendLate(ctx, func(late context.Context) { next(late, redis.NewCmd(late, cmd.Args()...)) })
		}
		if err == nil && c.action == "duplicate" {
			faultpoint.Outside(func() { err = next(ctx, cmd) })
		}
		return c.settle(cmd, err)
	}
}

// ProcessPipelineHook sends the commands no rule keeps back in one round trip, as the caller asked; a duplicate
// would leave the pipeline or its transaction, so a pipeline cannot duplicate.
func (h hook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) (err error) {
		defer faultpoint.Guard()
		calls := make([]call, len(cmds))
		known := make([]bool, len(cmds))
		sent := make([]redis.Cmder, 0, len(cmds))
		var late []redis.Cmder
		for index, cmd := range cmds {
			calls[index], known[index] = h.decide(ctx, cmd)
			if known[index] && calls[index].action == "duplicate" {
				faultpoint.Abort("rule %s: a pipeline cannot duplicate %s", calls[index].rule.ID, calls[index].point)
			}
			if !known[index] || calls[index].sent() {
				sent = append(sent, cmd)
			}
			if known[index] && calls[index].late() {
				late = append(late, redis.NewCmd(ctx, cmd.Args()...))
			}
		}
		if len(sent) > 0 {
			faultpoint.Outside(func() { err = next(ctx, sent) })
		}
		// go-redis reads a transaction's replies by its MULTI and EXEC, so late commands of one keep them.
		if len(late) > 0 && cmds[0].Name() == "multi" {
			late = append(append([]redis.Cmder{redis.NewStatusCmd(ctx, "multi")}, late...), redis.NewSliceCmd(ctx, "exec"))
		}
		if len(late) > 0 {
			action.SendLate(ctx, func(lateCtx context.Context) { next(lateCtx, late) })
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
