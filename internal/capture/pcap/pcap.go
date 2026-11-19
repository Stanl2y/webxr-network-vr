//go:build pcap

// Package pcap replays classic .pcap files into packet records using
// gopacket's pure-Go pcapgo reader (no libpcap/Npcap needed).
//
// It is behind the "pcap" build tag so default builds stay dependency-light:
//
//	go build -tags pcap ./cmd/agent
package pcap

import (
	"context"
	"errors"
	"io"
	"os"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/Stanl2y/webxr-network-vr/internal/record"
)

// Parse converts one Ethernet frame into a record. ok is false for non-IPv4
// frames.
func Parse(data []byte, ts time.Time, dev uint8) (r record.Record, ok bool) {
	pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	ip4, _ := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if ip4 == nil {
		return r, false
	}
	copy(r.SrcIP[:], ip4.SrcIP.To4())
	copy(r.DstIP[:], ip4.DstIP.To4())
	r.Proto = uint8(ip4.Protocol)
	switch l4 := pkt.TransportLayer().(type) {
	case *layers.TCP:
		r.SrcPort, r.DstPort = uint16(l4.SrcPort), uint16(l4.DstPort)
	case *layers.UDP:
		r.SrcPort, r.DstPort = uint16(l4.SrcPort), uint16(l4.DstPort)
	}
	r.TsNs = uint64(ts.UnixNano())
	r.PktLen = uint16(min(len(data), 65535))
	r.Dev = dev
	r.Weight = 1
	r.FlowHash = record.FlowHash(r.SrcIP, r.DstIP, r.SrcPort, r.DstPort, r.Proto)
	return r, true
}

// Replay reads path and emits records. When realtime is true it sleeps to
// reproduce the capture's inter-packet gaps (gaps under 1 ms are coalesced).
// It returns the number of records emitted.
func Replay(ctx context.Context, path string, dev uint8, realtime bool, emit func(record.Record)) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	rd, err := pcapgo.NewReader(f)
	if err != nil {
		return 0, err
	}
	if lt := rd.LinkType(); lt != layers.LinkTypeEthernet {
		return 0, errors.New("pcap: only Ethernet captures are supported, got " + lt.String())
	}
	var n int
	var first time.Time
	start := time.Now()
	for {
		data, ci, err := rd.ReadPacketData()
		if errors.Is(err, io.EOF) {
			return n, nil
		}
		if err != nil {
			return n, err
		}
		if first.IsZero() {
			first = ci.Timestamp
		}
		if realtime {
			if wait := ci.Timestamp.Sub(first) - time.Since(start); wait > time.Millisecond {
				select {
				case <-ctx.Done():
					return n, ctx.Err()
				case <-time.After(wait):
				}
			}
		}
		if r, ok := Parse(data, ci.Timestamp, dev); ok {
			emit(r)
			n++
		}
	}
}
