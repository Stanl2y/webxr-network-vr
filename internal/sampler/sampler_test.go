package sampler

import (
	"testing"
	"time"

	"github.com/Stanl2y/webxr-network-vr/internal/record"
)

const tick = 50 * time.Millisecond

func TestK(t *testing.T) {
	cases := []struct {
		pps  float64
		want uint32
	}{
		{0, 1}, {49_999, 1}, {50_000, 1}, {50_001, 2}, {60_000, 2},
		{100_000, 2}, {100_001, 3}, {1_000_000, 20}, {1_600_000, 32}, {10_000_000, 32},
	}
	for _, c := range cases {
		if got := K(c.pps, 50_000, 32); got != c.want {
			t.Errorf("K(%v) = %d, want %d", c.pps, got, c.want)
		}
	}
}

// fwd returns a forwarded record for flow h at time ns.
func fwd(h uint32, ns uint64) record.Record {
	return record.Record{TsNs: ns, FlowHash: h, Proto: 6, PktLen: 100, Weight: 1}
}

func TestKAdaptsFromMeasuredRate(t *testing.T) {
	s := New(Config{})
	// 3,000 records in a 50 ms tick = 60,000 pps -> k = 2 next tick.
	for i := 0; i < 3000; i++ {
		s.Offer(fwd(uint32(i), uint64(i)*16_666))
	}
	_, st := s.Flush(tick)
	if st.K != 1 {
		t.Fatalf("first tick k = %d, want 1", st.K)
	}
	if st.PPS < 59_999 || st.PPS > 60_001 {
		t.Fatalf("pps = %v, want 60000", st.PPS)
	}
	if s.CurrentK() != 2 {
		t.Fatalf("next k = %d, want 2", s.CurrentK())
	}
}

func TestFlowSamplingKeepsWholeFlowsWithWeightK(t *testing.T) {
	s := New(Config{HeavyHitterPPS: 1e9, HeavyHitterBurst: 1e9})
	s.SetK(4)
	const flows = 20_000
	for i := 0; i < flows; i++ {
		s.Offer(fwd(uint32(i)*2654435761, 1))
	}
	out, st := s.Flush(tick)
	frac := float64(len(out)) / flows
	if frac < 0.22 || frac > 0.28 {
		t.Fatalf("kept fraction %.3f, want ~0.25", frac)
	}
	for _, r := range out {
		if r.Weight != 4 {
			t.Fatalf("weight %d, want 4", r.Weight)
		}
		if !Keeps(r.FlowHash, 4) {
			t.Fatalf("emitted a flow that should be sampled out")
		}
	}
	if st.SampledOut+st.Emitted != flows {
		t.Fatalf("sampled_out %d + emitted %d != %d", st.SampledOut, st.Emitted, flows)
	}
	// Same flow is consistently kept or rejected.
	s.SetK(4)
	h := out[0].FlowHash
	for i := 0; i < 5; i++ {
		s.Offer(fwd(h, uint64(i)*1e9))
	}
	if again, _ := s.Flush(tick); len(again) != 5 {
		t.Fatalf("kept flow emitted %d of 5", len(again))
	}
}

func TestHeavyHitterBucketPreservesWeight(t *testing.T) {
	s := New(Config{})
	const h = 0xabcdef
	const n = 2000 // one flow at 2,000 pps for one second
	var emitted, weight uint64
	for i := 0; i < n; i++ {
		s.Offer(fwd(h, uint64(i)*500_000))
		if (i+1)%100 == 0 { // flush every 50 ms of packet time
			out, _ := s.Flush(tick)
			s.SetK(1)
			for _, r := range out {
				emitted++
				weight += uint64(r.Weight)
			}
		}
	}
	// burst 10 + 200/s over ~1 s.
	if emitted < 200 || emitted > 215 {
		t.Fatalf("emitted %d records, want ~210", emitted)
	}
	if got := weight + uint64(s.Pending(h)); got != n {
		t.Fatalf("weight %d + pending %d = %d, want %d", weight, s.Pending(h), got, n)
	}
}

func drop(dev, q, reason uint8, ns uint64) record.Record {
	return record.Record{TsNs: ns, Dev: dev, Queue: q, Verdict: reason, PktLen: 64, Weight: 9}
}

func TestDropsAreNeverSampled(t *testing.T) {
	s := New(Config{})
	s.SetK(32)
	for i := 0; i < 500; i++ {
		s.Offer(drop(1, 2, record.ReasonQueueFull, uint64(i)))
	}
	out, st := s.Flush(tick)
	if len(out) != 500 || st.DropsAggregated {
		t.Fatalf("got %d records (agg=%v), want 500 raw drops", len(out), st.DropsAggregated)
	}
	for _, r := range out {
		if r.Weight != 1 || r.Aggregated() {
			t.Fatalf("raw drop has weight %d agg=%v", r.Weight, r.Aggregated())
		}
	}
}

func TestDropAggregationAboveThreshold(t *testing.T) {
	s := New(Config{})
	keys := []struct{ dev, q, reason uint8 }{
		{0, 0, record.ReasonQueueFull}, {0, 1, record.ReasonQueueFull}, {3, 1, record.ReasonPolicy},
	}
	for i := 0; i < 1500; i++ {
		k := keys[i%3]
		s.Offer(drop(k.dev, k.q, k.reason, uint64(i)))
	}
	s.Offer(fwd(7, 1))
	out, st := s.Flush(tick)
	if !st.DropsAggregated {
		t.Fatal("expected aggregation above 1,000 drops")
	}
	var agg int
	var total uint64
	for _, r := range out {
		if r.Dropped() {
			if !r.Aggregated() {
				t.Fatal("raw drop leaked through aggregation")
			}
			agg++
			total += uint64(r.Weight)
		}
	}
	if agg != 3 || total != 1500 {
		t.Fatalf("aggregates=%d total=%d, want 3 and 1500", agg, total)
	}
	if st.Drops != 1500 || st.Emitted != 4 {
		t.Fatalf("stats drops=%d emitted=%d", st.Drops, st.Emitted)
	}
}

func TestAggregateSplitsAtUint16(t *testing.T) {
	d := make([]record.Record, 70_000)
	for i := range d {
		d[i] = drop(0, 0, record.ReasonQueueFull, 1)
	}
	out := aggregate(d)
	if len(out) != 2 || out[0].Weight != 65535 || out[1].Weight != 70_000-65535 {
		t.Fatalf("split wrong: %+v", out)
	}
}

func TestIdleFlowsAreCollected(t *testing.T) {
	s := New(Config{FlowIdle: time.Second})
	s.Offer(fwd(1, 0))
	s.Offer(fwd(2, 5e9)) // flow 1 idle for 5 s
	for i := 0; i < 20; i++ {
		s.Flush(tick)
	}
	if _, ok := s.flows[1]; ok {
		t.Fatal("idle flow not collected")
	}
	if _, ok := s.flows[2]; !ok {
		t.Fatal("active flow collected")
	}
}
