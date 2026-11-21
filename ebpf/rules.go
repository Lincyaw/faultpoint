package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"maps"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"faultpoint"

	"golang.org/x/sys/unix"
)

const (
	kindSyscall      = "syscall"
	kindPacket       = "packet"
	actionFail       = "fail"
	actionCrash      = "crash"
	actionDelay      = "delay"
	actionDrop       = "drop"
	actionNegate     = "negate"
	directionEgress  = "egress"
	directionIngress = "ingress"
	wildcard         = "*"
	outcomeOK        = "ok"
	outcomeDelayed   = "delayed"
	outcomeDropped   = "dropped"
	// fq drops a packet whose departure time is further ahead than its horizon, which is ten seconds by default.
	fqHorizon = 10 * time.Second
)

// actions are the actions the agent implements at each kind it serves, as a plugin declares them to the core; it
// serves call and check points only in native functions, and an event point is only observed.
var actions = map[string][]string{kindSyscall: {actionFail, actionCrash}, kindPacket: {actionDelay, actionDrop},
	kindCall: {actionFail, actionCrash}, kindCheck: {actionNegate, actionCrash}, kindEvent: {}}

var directions = map[string]pointsDirection{directionEgress: pointsDirectionEGRESS, directionIngress: pointsDirectionINGRESS}

// errnos maps errno names to numbers, since x/sys/unix only maps numbers to names.
var errnos = func() map[string]syscall.Errno {
	byName := map[string]syscall.Errno{}
	for errno := syscall.Errno(1); errno < 4096; errno++ {
		if name := unix.ErrnoName(errno); name != "" {
			byName[name] = errno
		}
	}
	return byName
}()

// syscallTable numbers the syscalls the agent attaches to; a number never changes, since counts are keyed by it.
type syscallTable []string

func (table *syscallTable) number(name string) uint32 {
	index := slices.Index(*table, name)
	if index < 0 {
		*table = append(*table, name)
		index = len(*table) - 1
	}
	return uint32(index)
}

// injection is what the observations of a rule's injected executions carry; a crash has no outcome, as in the SDKs,
// and a native point's programs count its injections with the outcomes they produce.
type injection struct {
	rule    string
	point   string
	outcome string
}

// kernelRules are the rules of the agent's services in the shape of the kernel maps; a rule's index keys its trigger.
type kernelRules struct {
	experiment string
	injections []injection
	triggers   []pointsTrigger
	syscalls   map[pointsSyscallPoint]*pointsSyscallRuleList
	packets    map[pointsPacketSide]*pointsPacketRuleList
	delayed    map[pointsPacketSide]bool
	natives    map[uint32]*pointsNativeRuleList
}

// translate keeps the syscall, packet and native function rules of the configured services and checks that the agent
// can apply them; rules of other services and kinds, and call and check rules outside native functions, are left to
// the processes that serve them.
func translate(ruleset faultpoint.RuleSet, services []service, syscalls *syscallTable, points []nativePoint, seed int64) (*kernelRules, error) {
	translated := &kernelRules{
		experiment: ruleset.Experiment,
		syscalls:   map[pointsSyscallPoint]*pointsSyscallRuleList{},
		packets:    map[pointsPacketSide]*pointsPacketRuleList{},
		delayed:    map[pointsPacketSide]bool{},
		natives:    map[uint32]*pointsNativeRuleList{},
	}
	for _, rule := range ruleset.Rules {
		name, kind, locator, err := faultpoint.SplitPoint(rule.Point)
		if err != nil {
			return nil, err
		}
		served := slices.IndexFunc(services, func(s service) bool { return s.name == name })
		native := slices.IndexFunc(points, func(point nativePoint) bool { return point.id == rule.Point })
		nativeKind := kind == kindCall || kind == kindCheck
		if served < 0 || actions[kind] == nil || (nativeKind && native < 0 && !nativeLocator.MatchString(locator)) {
			continue
		}
		if nativeKind && native < 0 {
			return nil, fmt.Errorf("rule %s: no configured native function has point %s", rule.ID, rule.Point)
		}
		if !slices.Contains(actions[kind], rule.Action.Kind) {
			return nil, fmt.Errorf("rule %s: the agent implements %v at a %s point, not %s", rule.ID, actions[kind], kind, rule.Action.Kind)
		}
		if len(rule.Scope) > 0 {
			return nil, fmt.Errorf("rule %s: the kernel sees no baggage, so a %s rule has no scope", rule.ID, kind)
		}
		index := uint32(len(translated.triggers))
		var outcome string
		switch {
		case kind == kindSyscall:
			outcome, err = translated.addSyscall(rule, index, services[served].index, syscalls.number(locator))
		case kind == kindPacket:
			outcome, err = translated.addPacket(rule, index, services[served], locator)
		default:
			err = translated.addNative(rule, index, uint32(native), points[native])
		}
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", rule.ID, err)
		}
		translated.triggers = append(translated.triggers, trigger(rule, seed))
		translated.injections = append(translated.injections, injection{rule: rule.ID, point: rule.Point, outcome: outcome})
	}
	return translated, nil
}

// trigger seeds a rule's draws with FAULTPOINT_SEED and the rule id; a probability p injects below p * 2^32.
func trigger(rule faultpoint.Rule, seed int64) pointsTrigger {
	hash := fnv.New64a()
	fmt.Fprintf(hash, "%d:%s", seed, rule.ID)
	translated := pointsTrigger{Skip: uint64(rule.Trigger.Skip), Limit: math.MaxUint64, Threshold: 1 << 32, Seed: hash.Sum64()}
	if rule.Trigger.Limit != nil {
		translated.Limit = uint64(*rule.Trigger.Limit)
	}
	if rule.Trigger.Probability != nil {
		translated.Threshold = uint64(*rule.Trigger.Probability * (1 << 32))
	}
	return translated
}

// addSyscall adds a fail rule, which returns its errno, or a crash rule, which kills the process with SIGKILL and
// therefore cannot exit with the rule's code.
func (translated *kernelRules) addSyscall(rule faultpoint.Rule, index, service, number uint32) (string, error) {
	entry := pointsSyscallRule{Rule: index}
	outcome := ""
	if rule.Action.Kind == actionCrash {
		var crash struct {
			Code int `json:"code"`
		}
		if err := decodeParams(rule.Action.Params, &crash); err != nil {
			return "", err
		}
		entry.Crash = 1
	} else {
		var fail struct {
			Error string `json:"error"`
		}
		if err := decodeParams(rule.Action.Params, &fail); err != nil {
			return "", err
		}
		errno, known := errnos[fail.Error]
		if !known {
			return "", fmt.Errorf("a syscall fails with the name of an errno, such as ECONNREFUSED: %q", fail.Error)
		}
		entry.Error, outcome = int64(errno), fail.Error
	}
	point := pointsSyscallPoint{Service: service, Syscall: number}
	list := translated.syscalls[point]
	if list == nil {
		list = &pointsSyscallRuleList{}
		translated.syscalls[point] = list
	}
	if int(list.Count) == len(list.Rules) {
		return "", fmt.Errorf("a syscall point has at most %d rules", len(list.Rules))
	}
	list.Rules[list.Count] = entry
	list.Count++
	return outcome, nil
}

// addPacket adds a drop rule or a delay rule, whose packets leave once fq reaches their departure time.
func (translated *kernelRules) addPacket(rule faultpoint.Rule, index uint32, owner service, locator string) (string, error) {
	direction, address, port, err := parsePacketLocator(locator)
	if err != nil {
		return "", err
	}
	if !slices.ContainsFunc(owner.devices, func(device deviceOptions) bool { return device.Transmits == direction }) {
		return "", fmt.Errorf("no device of service %s is configured to transmit its %s packets", owner.name, direction)
	}
	side := pointsPacketSide{Service: owner.index, Direction: uint32(directions[direction])}
	entry := pointsPacketRule{Rule: index, Port: port, Address: address.As16()}
	if !address.IsValid() {
		entry.AnyAddress = 1
	}
	outcome := outcomeDropped
	if rule.Action.Kind == actionDelay {
		var delay struct {
			MS int64 `json:"ms"`
		}
		if err := decodeParams(rule.Action.Params, &delay); err != nil {
			return "", err
		}
		duration := time.Duration(delay.MS) * time.Millisecond
		if duration <= 0 || duration >= fqHorizon {
			return "", fmt.Errorf("a packet delay is positive and below the fq horizon of %s: %d ms", fqHorizon, delay.MS)
		}
		entry.DelayNs, outcome = uint64(duration), outcomeDelayed
		translated.delayed[side] = true
	} else if err := decodeParams(rule.Action.Params, &struct{}{}); err != nil {
		return "", err
	}
	list := translated.packets[side]
	if list == nil {
		list = &pointsPacketRuleList{}
		translated.packets[side] = list
	}
	if int(list.Count) == len(list.Rules) {
		return "", fmt.Errorf("the %s packets of a service have at most %d rules", direction, len(list.Rules))
	}
	list.Rules[list.Count] = entry
	list.Count++
	return outcome, nil
}

// addNative adds a fail rule, which writes the result registers with the words of the error it names, a negate rule,
// which flips a check's result at its returns, or a crash rule, which kills the process with SIGKILL at the entry.
func (translated *kernelRules) addNative(rule faultpoint.Rule, index, point uint32, function nativePoint) error {
	entry := pointsNativeRule{Rule: index}
	switch rule.Action.Kind {
	case actionFail:
		var fail struct {
			Error string `json:"error"`
		}
		if err := decodeParams(rule.Action.Params, &fail); err != nil {
			return err
		}
		writes, known := function.errors[fail.Error]
		if !known {
			return fmt.Errorf("%s fails with one of the errors configured for it, %v, not %q", function.id,
				slices.Sorted(maps.Keys(function.errors)), fail.Error)
		}
		entry.Action, entry.Writes = pointsNativeActionFAIL, uint32(copy(entry.Write[:], writes))
	case actionCrash:
		var crash struct {
			Code int `json:"code"`
		}
		if err := decodeParams(rule.Action.Params, &crash); err != nil {
			return err
		}
		entry.Action = pointsNativeActionCRASH
	default:
		if err := decodeParams(rule.Action.Params, &struct{}{}); err != nil {
			return err
		}
		entry.Action = pointsNativeActionNEGATE
	}
	list := translated.natives[point]
	if list == nil {
		list = &pointsNativeRuleList{}
		translated.natives[point] = list
	}
	if int(list.Count) == len(list.Rules) {
		return fmt.Errorf("a native point has at most %d rules", len(list.Rules))
	}
	list.Rules[list.Count] = entry
	list.Count++
	return nil
}

// parsePacketLocator reads <egress|ingress>:<ip|*>:<port|*>; an IPv6 address keeps its colons, so the port follows
// the last one. An IPv4 address is kept IPv4-mapped, as the kernel program compares it.
func parsePacketLocator(locator string) (string, netip.Addr, uint16, error) {
	direction, rest, found := strings.Cut(locator, ":")
	_, known := directions[direction]
	separator := strings.LastIndex(rest, ":")
	if !found || !known || separator < 0 {
		return "", netip.Addr{}, 0, fmt.Errorf("a packet locator is <egress|ingress>:<ip|*>:<port|*>: %q", locator)
	}
	var address netip.Addr
	if text := rest[:separator]; text != wildcard {
		parsed, err := netip.ParseAddr(text)
		if err != nil {
			return "", netip.Addr{}, 0, err
		}
		address = parsed
	}
	var port uint64
	if text := rest[separator+1:]; text != wildcard {
		parsed, err := strconv.ParseUint(text, 10, 16)
		if err != nil || parsed == 0 {
			return "", netip.Addr{}, 0, fmt.Errorf("a packet locator's port is * or 1 to 65535: %q", locator)
		}
		port = parsed
	}
	return direction, address, uint16(port), nil
}

func decodeParams(params json.RawMessage, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(params))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}
