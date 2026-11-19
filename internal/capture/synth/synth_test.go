package synth

import (
	"testing"

	"github.com/Stanl2y/webxr-network-vr/internal/record"
)

func runFor(g *Generator, seconds int) (all, drops int, flows map[uint32]int) {
	flows = map[uint32]int{}
	const step = 1_000_000 // 1 ms
	for ns := uint64(0); ns < uint64(seconds)*1e9; ns += step {
		g.Step(ns, step, func(r record.Record) {
			all++
			flows[r.FlowHash]++
			if r.Dropped() {
				drops++
			}
		})
	}
	return
}

func TestRateMatchesPPSIncludingBursts(t *testing.T) {
	g := New(Config{PPS: 60_000})
	all, _, _ := runFor(g, 2)
	// 2 s at 60k with one 250 ms window at 3x = 60k*2 + 60k*2*0.25 = 150k
	if all < 149_000 || all > 151_000 {
		t.Fatalf("emitted %d records in 2 s, want ~150,000", all)
	}
}

func TestBurstsCauseQueueDrops(t *testing.T) {
	g := New(Config{PPS: 20_000})
	_, drops, _ := runFor(g, 2)
	if drops == 0 {
		t.Fatal("expected queue-full drops during micro-bursts")
	}
}

func TestZipfProducesHeavyHitters(t *testing.T) {
	g := New(Config{PPS: 50_000})
	all, _, flows := runFor(g, 1)
	max := 0
	for _, n := range flows {
		if n > max {
			max = n
		}
	}
	if float64(max) < 0.02*float64(all) {
		t.Fatalf("top flow has %d of %d packets; expected a heavy hitter", max, all)
	}
}

func TestFlowHashAndPlacementAreConsistent(t *testing.T) {
	g := New(Config{Devs: 3, Queues: 5})
	g.Step(0, 10_000_000, func(r record.Record) {
		if r.FlowHash != record.FlowHash(r.SrcIP, r.DstIP, r.SrcPort, r.DstPort, r.Proto) {
			t.Fatalf("flow hash mismatch: %+v", r)
		}
		if r.Dev >= 3 || r.Queue >= 5 {
			t.Fatalf("placement out of range: dev=%d queue=%d", r.Dev, r.Queue)
		}
	})
}

func TestDeterministic(t *testing.T) {
	a, _, _ := runFor(New(Config{PPS: 5000, Seed: 7}), 1)
	b, _, _ := runFor(New(Config{PPS: 5000, Seed: 7}), 1)
	if a != b {
		t.Fatalf("same seed gave %d vs %d", a, b)
	}
}
