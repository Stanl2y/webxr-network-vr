//go:build !linux

// Package xdp is Linux-only; on other systems Run always fails.
package xdp

import (
	"context"
	"errors"

	"github.com/Stanl2y/webxr-network-vr/internal/record"
)

// Supported reports whether this build can attach XDP programs.
const Supported = false

// ErrUnsupported is returned by Run on non-Linux systems.
var ErrUnsupported = errors.New("xdp: eBPF/XDP capture is only available on Linux; use --synth or --pcap")

// Run always returns ErrUnsupported on this OS.
func Run(context.Context, string, string, uint8, func(record.Record)) error {
	return ErrUnsupported
}
