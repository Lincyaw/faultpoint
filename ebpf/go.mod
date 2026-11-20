module faultpoint/ebpf

go 1.26.0

replace faultpoint => ../go

require (
	faultpoint v0.0.0-00010101000000-000000000000
	github.com/cilium/ebpf v0.22.0
	github.com/vishvananda/netlink v1.3.1
	github.com/vishvananda/netns v0.0.5
	golang.org/x/sys v0.50.0
)

tool github.com/cilium/ebpf/cmd/bpf2go
