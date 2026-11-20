#include "vmlinux.h"
#include <bpf_helpers.h>
#include <bpf_endian.h>

#define MAX_RULES 256
#define MAX_POINT_RULES 8
#define MAX_CGROUP_LEVEL 32
#define SIGKILL 9
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD

char LICENSE[] SEC("license") = "Dual MIT/GPL";

enum direction { EGRESS, INGRESS };

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

/* The syscall a task is in when it was injected, so its exit is not counted as natural. */
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

SEC("tracepoint")
int observe_syscall(struct syscall_trace_exit *ctx)
{
	__u32 *service = current_service();
	if (!service)
		return 0;
	__u32 syscall = bpf_get_attach_cookie(ctx);
	__u64 task = bpf_get_current_pid_tgid();
	__u32 *mark = bpf_map_lookup_elem(&marks, &task);
	if (mark && *mark == syscall) {
		bpf_map_delete_elem(&marks, &task);
		return 0;
	}
	struct natural_key key = {.service = *service, .syscall = syscall, .error = ctx->ret < 0 ? -ctx->ret : 0};
	__u64 one = 1;
	if (bpf_map_update_elem(&natural, &key, &one, BPF_NOEXIST) == 0)
		return 0;
	__u64 *count = bpf_map_lookup_elem(&natural, &key);
	if (count)
		*count += 1;
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
