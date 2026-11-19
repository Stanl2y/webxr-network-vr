// Package synth generates realistic-looking packet records without any
// capture privileges, so the agent and viewer run on any OS (including
// Windows) and in CI.
//
// Model: a fixed set of flows with Zipf-distributed popularity (a few heavy
// hitters, a long tail) is spread over Devs x Queues output queues. Each
// queue drains at a fixed service rate; every 2 s a 250 ms micro-burst
// triples the offered load so hot queues overflow and produce queue-full
// drops. A small fraction of packets is dropped by "policy".
package synth

import (
	"context"
	"math/rand"
	"time"

	"github.com/Stanl2y/webxr-network-vr/internal/record"
)

// Config controls the generator. Zero fields take defaults.
type Config struct {
	PPS      int     // offered packets per second (default 10,000)
	Flows    int     // distinct flows (default 4,096)
	Devs     int     // devices (default 4)
	Queues   int     // queues per device (default 4)
	QueueCap float64 // queue capacity in packets (default 256)
	// Headroom is service rate / average per-queue load (default 2.0).
	// Bursts offer 3x load, so queues overflow only during bursts or when
	// heavy hitters hash onto the same queue.
	Headroom float64
	Seed     int64
}

func (c Config) withDefaults() Config {
	if c.PPS <= 0 {
		c.PPS = 10_000
	}
	if c.Flows <= 0 {
		c.Flows = 4096
	}
	if c.Devs <= 0 {
		c.Devs = 4
	}
	if c.Queues <= 0 {
		c.Queues = 4
	}
	if c.QueueCap <= 0 {
		c.QueueCap = 256
	}
	if c.Headroom <= 0 {
		c.Headroom = 2.0
	}
	if c.Seed == 0 {
		c.Seed = 1
	}
	return c
}

type flow struct {
	src, dst     [4]byte
	sport, dport uint16
	proto        uint8
	hash         uint32
	dev, queue   uint8
	bigPackets   bool
}

// Generator is deterministic for a given Config.
type Generator struct {
	cfg     Config
	rng     *rand.Rand
	zipf    *rand.Zipf
	flows   []flow
	depth   []float64 // per dev*queue
	service float64   // packets/s drained per queue
	carry   float64   // fractional packets carried between steps
}

// New builds the flow table.
func New(cfg Config) *Generator {
	cfg = cfg.withDefaults()
	rng := rand.New(rand.NewSource(cfg.Seed))
	g := &Generator{
		cfg:   cfg,
		rng:   rng,
		zipf:  rand.NewZipf(rng, 1.15, 4, uint64(cfg.Flows-1)),
		flows: make([]flow, cfg.Flows),
		depth: make([]float64, cfg.Devs*cfg.Queues),
	}
	g.service = float64(cfg.PPS) / float64(len(g.depth)) * cfg.Headroom
	for i := range g.flows {
		f := &g.flows[i]
		f.src = [4]byte{10, byte(rng.Intn(4)), byte(rng.Intn(256)), byte(1 + rng.Intn(254))}
		f.dst = [4]byte{172, 16, byte(rng.Intn(8)), byte(1 + rng.Intn(254))}
		switch r := rng.Float64(); {
		case r < 0.7:
			f.proto, f.dport = 6, []uint16{443, 80, 22, 5432}[rng.Intn(4)]
		case r < 0.97:
			f.proto, f.dport = 17, []uint16{53, 443, 4789}[rng.Intn(3)]
		default:
			f.proto = 1 // ICMP, no ports
		}
		if f.proto != 1 {
			f.sport = uint16(32768 + rng.Intn(28000))
		}
		f.hash = record.FlowHash(f.src, f.dst, f.sport, f.dport, f.proto)
		f.dev = uint8(f.hash % uint32(cfg.Devs))
		f.queue = uint8((f.hash >> 8) % uint32(cfg.Queues))
		f.bigPackets = rng.Float64() < 0.4
	}
	return g
}

// Burst reports whether t (ns since start) falls in a micro-burst window.
func Burst(nowNs uint64) bool { return nowNs%2_000_000_000 < 250_000_000 }

// Step emits the packets due in the interval (fromNs, fromNs+dtNs].
// It returns the number of records emitted.
func (g *Generator) Step(fromNs, dtNs uint64, emit func(record.Record)) int {
	rate := float64(g.cfg.PPS)
	if Burst(fromNs) {
		rate *= 3
	}
	want := rate*float64(dtNs)/1e9 + g.carry
	n := int(want)
	g.carry = want - float64(n)

	drain := g.service * float64(dtNs) / 1e9
	for i := range g.depth {
		g.depth[i] -= drain
		if g.depth[i] < 0 {
			g.depth[i] = 0
		}
	}
	for i := 0; i < n; i++ {
		f := &g.flows[g.zipf.Uint64()]
		ts := fromNs + uint64(i+1)*dtNs/uint64(n)
		r := record.Record{
			TsNs: ts, FlowHash: f.hash, SrcIP: f.src, DstIP: f.dst,
			SrcPort: f.sport, DstPort: f.dport, Proto: f.proto,
			Dev: f.dev, Queue: f.queue, Weight: 1,
		}
		if f.bigPackets {
			r.PktLen = 1514
		} else {
			r.PktLen = uint16(64 + g.rng.Intn(512))
		}
		qi := int(f.dev)*g.cfg.Queues + int(f.queue)
		switch {
		case g.depth[qi] >= g.cfg.QueueCap:
			r.Verdict = record.ReasonQueueFull
		case g.rng.Intn(10_000) == 0:
			r.Verdict = record.ReasonPolicy
		default:
			g.depth[qi]++
		}
		emit(r)
	}
	return n
}

// QueueDepths returns a copy of the current per-queue depth (dev-major).
func (g *Generator) QueueDepths() []float64 { return append([]float64(nil), g.depth...) }

// Run paces Step against the wall clock in 2 ms slices until ctx ends.
// Timestamps are ns since Run started.
func (g *Generator) Run(ctx context.Context, emit func(record.Record)) {
	start := time.Now()
	t := time.NewTicker(2 * time.Millisecond)
	defer t.Stop()
	var last uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			now := uint64(time.Since(start))
			g.Step(last, now-last, emit)
			last = now
		}
	}
}
