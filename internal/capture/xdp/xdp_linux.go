//go:build linux

// Package xdp loads bpf/xdp.o, attaches it to an interface and streams the
// 32-byte records it writes into the "events" ring buffer. Linux only; needs
// CAP_BPF + CAP_NET_ADMIN (or root) and a kernel with BPF ring buffer (5.8+).
package xdp

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/Stanl2y/webxr-network-vr/internal/record"
)

// Supported reports whether this build can attach XDP programs.
const Supported = true

// Run attaches objPath's xdp_capture program to iface and emits records
// until ctx is cancelled. dev is stamped into every record.
func Run(ctx context.Context, objPath, iface string, dev uint8, emit func(record.Record)) error {
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return fmt.Errorf("load %s: %w", objPath, err)
	}
	var objs struct {
		Prog   *ebpf.Program `ebpf:"xdp_capture"`
		Events *ebpf.Map     `ebpf:"events"`
	}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return fmt.Errorf("load into kernel: %w", err)
	}
	defer objs.Prog.Close()
	defer objs.Events.Close()

	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		return err
	}
	l, err := link.AttachXDP(link.XDPOptions{Program: objs.Prog, Interface: ifc.Index})
	if err != nil {
		return fmt.Errorf("attach xdp to %s: %w", iface, err)
	}
	defer l.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		rd.Close()
	}()
	for {
		rec, err := rd.Read()
		if errors.Is(err, ringbuf.ErrClosed) {
			return nil
		}
		if err != nil {
			return err
		}
		r, err := record.Decode(rec.RawSample)
		if err != nil {
			continue
		}
		r.Dev = dev
		emit(r)
	}
}
