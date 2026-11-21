#include "vmlinux.h"
#include <bpf_helpers.h>
#include <bpf_endian.h>

#define MAX_RULES 256
#define MAX_POINT_RULES 8
#define MAX_CGROUP_LEVEL 32
#define MAX_NATIVE_SITES 4096
#define MAX_RESULT_REGISTERS 4
#define MAX_EVENTS 4096
#define SIGKILL 9
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD

char LICENSE[] SEC("license") = "Dual MIT/GPL";

enum direction { EGRESS, INGRESS };
enum register_name { AX, BX, CX, DX, SI, DI, R8, R9, R10, R11 };
enum result_type { INT32, INT64, POINTER, BOOL };
enum error_rule { NONZERO, NEGATIVE, ZERO };
enum native_action { FAIL, CRASH, NEGATE };

struct trigger {
	__u64 skip;
	__u64 limit;
	__u64 threshold;
	__u64 seed;
	__u64 matches;
	__u64 injections;
};

struct syscall_point {
	__u32 service;
	__u32 syscall;
};

struct syscall_rule {
	__u32 rule;
	__u32 crash;
	__s64 error;
};

struct syscall_rule_list {
	__u32 count;
	struct syscall_rule rules[MAX_POINT_RULES];
};

struct packet_side {
	__u32 service;
	enum direction direction;
};

struct packet_rule {
	__u32 rule;
	__u16 port;
	__u8 any_address;
	__u8 address[16];
	__u64 delay_ns;
};

struct packet_rule_list {
	__u32 count;
	struct packet_rule rules[MAX_POINT_RULES];
};

struct natural_key {
	__u32 service;
	__u32 syscall;
	__s32 error;
};

struct peer {
	__u8 address[16];
	__u16 port;
};

/* An entry or a return of a native function point; address is its link-time address, so ip - address is the load
 * bias of the file in the process. */
struct native_site {
	__u32 point;
	__u32 service;
	__u64 address;
	enum register_name outcome;
	enum result_type type;
	enum error_rule error;
	__u32 conditional;
	enum register_name condition;
	__u64 mask;
	__u64 equals;
};

/* A word written into a result register: the value, or the word at the link-time address value. */
struct native_write {
	enum register_name target;
	__u32 from_memory;
	__u64 value;
};

struct native_rule {
	__u32 rule;
	enum native_action action;
	__u32 writes;
	struct native_write write[MAX_RESULT_REGISTERS];
};

struct native_rule_list {
	__u32 count;
	struct native_rule rules[MAX_POINT_RULES];
};

/* An outcome of a native point: flagged is a failed call or a true check, value the integer result of a failed call,
 * and rule is 0 for a natural result or the injecting rule's index plus one. */
struct native_key {
	__u32 point;
	__u16 rule;
	__u16 flagged;
	__s64 value;
};

/* Bit n is set when a configured cgroup is n levels below the root. */
volatile const __u32 cgroup_levels;
volatile const __u32 packet_service;
volatile const enum direction packet_direction;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);
	__type(value, __u32);
} cgroup_services SEC(".maps");

/* A task the agent injected a syscall in, with the syscall's number in the agent's table, so the syscall's exit is not
 * counted as natural. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, __u32);
} marks SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct natural_key);
	__type(value, __u64);
} natural SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_RULES);
	__type(key, __u32);
	__type(value, struct trigger);
} triggers SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_RULES);
	__type(key, struct syscall_point);
	__type(value, struct syscall_rule_list);
} syscall_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_RULES);
	__type(key, struct packet_side);
	__type(value, struct packet_rule_list);
} packet_rules SEC(".maps");

/* Indexed by the cookie of a native probe. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_NATIVE_SITES);
	__type(key, __u32);
	__type(value, struct native_site);
} native_sites SEC(".maps");

/* Keyed by native point; read at the returns as well as the entries, so it lives as long as the returns' probes. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_RULES);
	__type(key, __u32);
	__type(value, struct native_rule_list);
} native_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct native_key);
	__type(value, __u64);
} native_outcomes SEC(".maps");

/* The service of each event point, indexed by the cookie of its probes. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_EVENTS);
	__type(key, __u32);
	__type(value, __u32);
} event_services SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, MAX_EVENTS);
	__type(key, __u32);
	__type(value, __u64);
} event_counts SEC(".maps");

static __always_inline __u32 *current_service(void)
{
	__u32 *service = NULL;
	for (int level = 0; level < MAX_CGROUP_LEVEL; level++) {
		if (!(cgroup_levels & (1u << level)))
			continue;
		__u64 cgroup = bpf_get_current_ancestor_cgroup_id(level);
		__u32 *found = bpf_map_lookup_elem(&cgroup_services, &cgroup);
		if (found)
			service = found;
	}
	return service;
}

/* Draws the n-th number of a SplitMix64 sequence, so a rule's draws depend only on its seed and match count. */
static __always_inline __u64 draw(__u64 seed, __u64 n)
{
	__u64 x = seed + (n + 1) * 0x9e3779b97f4a7c15ULL;
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
	x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
	return x ^ (x >> 31);
}

static __always_inline bool fires(__u32 rule)
{
	struct trigger *trigger = bpf_map_lookup_elem(&triggers, &rule);
	if (!trigger)
		return false;
	__u64 seen = __sync_fetch_and_add(&trigger->matches, 1);
	if (seen < trigger->skip || (draw(trigger->seed, seen) >> 32) >= trigger->threshold)
		return false;
	return __sync_fetch_and_add(&trigger->injections, 1) < trigger->limit;
}

static __always_inline void increment(void *counts, const void *key)
{
	__u64 one = 1;
	if (bpf_map_update_elem(counts, key, &one, BPF_NOEXIST) == 0)
		return;
	__u64 *count = bpf_map_lookup_elem(counts, key);
	if (count)
		__sync_fetch_and_add(count, 1);
}

SEC("kprobe")
int inject_syscall(struct pt_regs *ctx)
{
	__u32 *service = current_service();
	if (!service)
		return 0;
	struct syscall_point point = {.service = *service, .syscall = bpf_get_attach_cookie(ctx)};
	struct syscall_rule_list *rules = bpf_map_lookup_elem(&syscall_rules, &point);
	if (!rules)
		return 0;
	for (__u32 i = 0; i < MAX_POINT_RULES && i < rules->count; i++) {
		struct syscall_rule *rule = &rules->rules[i];
		if (!fires(rule->rule))
			continue;
		__u64 task = bpf_get_current_pid_tgid();
		bpf_map_update_elem(&marks, &task, &point.syscall, BPF_ANY);
		if (rule->crash)
			bpf_send_signal(SIGKILL);
		else
			bpf_override_return(ctx, -rule->error);
		return 0;
	}
	return 0;
}

/* At the exit of every syscall, its number and errno are counted for the service of the current task; a task exits
 * the syscall it is in before it enters another, so a mark the injection left is that syscall's, not natural. */
SEC("tracepoint/raw_syscalls/sys_exit")
int observe_syscalls(struct trace_event_raw_sys_exit *ctx)
{
	__u32 *service = current_service();
	if (!service || ctx->id < 0)
		return 0;
	__u64 task = bpf_get_current_pid_tgid();
	if (bpf_map_lookup_elem(&marks, &task)) {
		bpf_map_delete_elem(&marks, &task);
		return 0;
	}
	struct natural_key key = {.service = *service, .syscall = ctx->id, .error = ctx->ret < 0 ? -ctx->ret : 0};
	increment(&natural, &key);
	return 0;
}

/* The verifier accepts a context access only at a constant offset, so each register has its own instruction. */
#define LOAD_REGISTER(field) asm volatile("%0 = *(u64 *)(%1 + %2)" : "=r"(value) : "r"(ctx), "i"(__builtin_offsetof(struct pt_regs, field)))
#define STORE_REGISTER(field) asm volatile("*(u64 *)(%0 + %1) = %2" :: "r"(ctx), "i"(__builtin_offsetof(struct pt_regs, field)), "r"(value) : "memory")

static __always_inline __u64 get_register(struct pt_regs *ctx, enum register_name name)
{
	__u64 value;
	switch (name) {
	case AX: LOAD_REGISTER(ax); break;
	case BX: LOAD_REGISTER(bx); break;
	case CX: LOAD_REGISTER(cx); break;
	case DX: LOAD_REGISTER(dx); break;
	case SI: LOAD_REGISTER(si); break;
	case DI: LOAD_REGISTER(di); break;
	case R8: LOAD_REGISTER(r8); break;
	case R9: LOAD_REGISTER(r9); break;
	case R10: LOAD_REGISTER(r10); break;
	default: LOAD_REGISTER(r11); break;
	}
	return value;
}

static __always_inline void set_register(struct pt_regs *ctx, enum register_name name, __u64 value)
{
	switch (name) {
	case AX: STORE_REGISTER(ax); break;
	case BX: STORE_REGISTER(bx); break;
	case CX: STORE_REGISTER(cx); break;
	case DX: STORE_REGISTER(dx); break;
	case SI: STORE_REGISTER(si); break;
	case DI: STORE_REGISTER(di); break;
	case R8: STORE_REGISTER(r8); break;
	case R9: STORE_REGISTER(r9); break;
	case R10: STORE_REGISTER(r10); break;
	default: STORE_REGISTER(r11); break;
	}
}

/* Returns the site of the probe that fired when the current task belongs to the site's service. */
static __always_inline struct native_site *current_site(struct pt_regs *ctx)
{
	__u32 *service = current_service();
	if (!service)
		return NULL;
	__u32 cookie = bpf_get_attach_cookie(ctx);
	struct native_site *site = bpf_map_lookup_elem(&native_sites, &cookie);
	return site && site->service == *service ? site : NULL;
}

static __always_inline void count_native(const struct native_site *site, __u32 rule, __u64 result)
{
	struct native_key key = {.point = site->point, .rule = rule};
	__s64 value = site->type == INT32 ? (__s32)result : (__s64)result;
	if (site->type == BOOL)
		key.flagged = (result & 0xff) != 0;
	else if (site->error == NEGATIVE)
		key.flagged = value < 0;
	else if (site->error == ZERO)
		key.flagged = value == 0;
	else
		key.flagged = value != 0;
	if (key.flagged && (site->type == INT32 || site->type == INT64))
		key.value = value;
	increment(&native_outcomes, &key);
}

/* Reads the words a rule writes before its trigger counts the execution, so a word that cannot be read skips it. */
static __always_inline int read_words(const struct native_rule *rule, __u64 bias, __u64 *words)
{
	for (__u32 i = 0; i < MAX_RESULT_REGISTERS && i < rule->writes; i++) {
		const struct native_write *write = &rule->write[i];
		words[i] = write->value;
		if (write->from_memory && bpf_probe_read_user(&words[i], sizeof(words[i]), (void *)(write->value + bias)))
			return -1;
	}
	return 0;
}

/* At a function's entry, a fail rule writes the result registers and returns to the caller as ret would, so the
 * function's body does not run; a crash rule kills the process before the body runs. */
SEC("uprobe")
int enter_native(struct pt_regs *ctx)
{
	struct native_site *site = current_site(ctx);
	if (!site || (site->conditional && (get_register(ctx, site->condition) & site->mask) != site->equals))
		return 0;
	struct native_rule_list *rules = bpf_map_lookup_elem(&native_rules, &site->point);
	__u64 caller;
	if (!rules || bpf_probe_read_user(&caller, sizeof(caller), (void *)ctx->sp))
		return 0;
	for (__u32 i = 0; i < MAX_POINT_RULES && i < rules->count; i++) {
		struct native_rule *rule = &rules->rules[i];
		__u64 words[MAX_RESULT_REGISTERS] = {};
		if (rule->action == NEGATE || read_words(rule, ctx->ip - site->address, words) || !fires(rule->rule))
			continue;
		if (rule->action == CRASH) {
			bpf_send_signal(SIGKILL);
			return 0;
		}
		for (__u32 w = 0; w < MAX_RESULT_REGISTERS && w < rule->writes; w++)
			set_register(ctx, rule->write[w].target, words[w]);
		ctx->ip = caller;
		ctx->sp += 8;
		count_native(site, rule->rule + 1, get_register(ctx, site->outcome));
		return 0;
	}
	return 0;
}

/* At each return of a function, the result is counted; a negate rule flips the low byte of a bool before ret runs. */
SEC("uprobe")
int leave_native(struct pt_regs *ctx)
{
	struct native_site *site = current_site(ctx);
	if (!site)
		return 0;
	__u64 result = get_register(ctx, site->outcome);
	struct native_rule_list *rules = bpf_map_lookup_elem(&native_rules, &site->point);
	for (__u32 i = 0; rules && i < MAX_POINT_RULES && i < rules->count; i++) {
		struct native_rule *rule = &rules->rules[i];
		if (rule->action != NEGATE || !fires(rule->rule))
			continue;
		result = (result & ~0xffULL) | !(result & 0xff);
		set_register(ctx, site->outcome, result);
		count_native(site, rule->rule + 1, result);
		return 0;
	}
	count_native(site, 0, result);
	return 0;
}

static __always_inline void count_event(void *ctx)
{
	__u32 *service = current_service();
	if (!service)
		return;
	__u32 event = bpf_get_attach_cookie(ctx);
	__u32 *owner = bpf_map_lookup_elem(&event_services, &event);
	__u64 *count = bpf_map_lookup_elem(&event_counts, &event);
	if (owner && count && *owner == *service)
		__sync_fetch_and_add(count, 1);
}

/* At a site of a USDT probe, the probe fired. */
SEC("uprobe")
int observe_usdt(struct pt_regs *ctx)
{
	count_event(ctx);
	return 0;
}

/* At a tracepoint, the event fired in the current task. */
SEC("tracepoint")
int observe_tracepoint(void *ctx)
{
	count_event(ctx);
	return 0;
}

static __always_inline int read_peer(struct __sk_buff *skb, struct peer *peer)
{
	__u8 protocol;
	__u32 transport;
	if (skb->protocol == bpf_htons(ETH_P_IP)) {
		struct iphdr ip;
		if (bpf_skb_load_bytes_relative(skb, 0, &ip, sizeof(ip), BPF_HDR_START_NET))
			return -1;
		__be32 address = packet_direction == EGRESS ? ip.daddr : ip.saddr;
		__builtin_memset(peer->address, 0, 10);
		peer->address[10] = 0xff;
		peer->address[11] = 0xff;
		__builtin_memcpy(&peer->address[12], &address, 4);
		protocol = ip.frag_off & bpf_htons(0x1fff) ? 0 : ip.protocol;
		transport = ip.ihl * 4;
	} else if (skb->protocol == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr ip;
		if (bpf_skb_load_bytes_relative(skb, 0, &ip, sizeof(ip), BPF_HDR_START_NET))
			return -1;
		__builtin_memcpy(peer->address, packet_direction == EGRESS ? &ip.daddr : &ip.saddr, 16);
		protocol = ip.nexthdr;
		transport = sizeof(ip);
	} else {
		return -1;
	}
	peer->port = 0;
	if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
		__be16 ports[2];
		if (bpf_skb_load_bytes_relative(skb, transport, ports, sizeof(ports), BPF_HDR_START_NET))
			return -1;
		peer->port = bpf_ntohs(packet_direction == EGRESS ? ports[1] : ports[0]);
	}
	return 0;
}

static __always_inline bool matches(const struct packet_rule *rule, const struct peer *peer)
{
	if (rule->port && rule->port != peer->port)
		return false;
	if (rule->any_address)
		return true;
	for (int i = 0; i < 16; i++)
		if (rule->address[i] != peer->address[i])
			return false;
	return true;
}

/* Attached on the egress of a device that transmits the packets of one service in one direction. */
SEC("tcx/egress")
int inject_packet(struct __sk_buff *skb)
{
	struct packet_side side = {.service = packet_service, .direction = packet_direction};
	struct packet_rule_list *rules = bpf_map_lookup_elem(&packet_rules, &side);
	struct peer peer;
	if (!rules || read_peer(skb, &peer))
		return TCX_NEXT;
	for (__u32 i = 0; i < MAX_POINT_RULES && i < rules->count; i++) {
		struct packet_rule *rule = &rules->rules[i];
		if (!matches(rule, &peer) || !fires(rule->rule))
			continue;
		if (!rule->delay_ns)
			return TCX_DROP;
		skb->tstamp = bpf_ktime_get_ns() + rule->delay_ns;
		return TCX_NEXT;
	}
	return TCX_NEXT;
}
