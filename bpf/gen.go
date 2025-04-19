// bpf/gen.go
package bpf

import (
	"C"
)

//go:generatego run github.com/cilium/ebpf/cmd/bpf2go -tags linux xdp_prog xdp_prog.c
