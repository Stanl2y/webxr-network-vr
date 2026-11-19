//go:build pcap

package main

import (
	"context"

	"github.com/Stanl2y/webxr-network-vr/internal/capture/pcap"
	"github.com/Stanl2y/webxr-network-vr/internal/record"
)

func init() {
	pcapReplay = func(ctx context.Context, path string, realtime bool, emit func(record.Record)) (int, error) {
		return pcap.Replay(ctx, path, 0, realtime, emit)
	}
}
