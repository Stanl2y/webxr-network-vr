// Package sampler reduces a raw packet-record stream to a size the viewer can
// render at 20 Hz while keeping totals reconstructible from sample_weight.
//
// Rules (applied per record, in this order):
//
//  1. Drops are never sampled. Every dropped record is kept with weight 1.
//     If more than DropAggThreshold drops arrive within one tick, the tick's
//     drops are instead collapsed into one aggregate record per
//     (dev, queue, reason) whose weight is the drop count.
//  2. Forwarded packets are flow-sampled: a flow is kept when
//     mix(flow_hash) % k == 0, with k = ceil(pps / TargetPPS) clamped to
//     [1, MaxK]. pps is measured over the previous tick. Kept records carry
//     sample_weight = k, so sum(weight) estimates the real packet count.
//  3. A kept flow may emit at most HeavyHitterPPS records per second
//     (token bucket). Throttled packets are not lost: their weight is carried
//     into the flow's next emitted record.
package sampler

import (
	"math"
	"time"

	"github.com/Stanl2y/webxr-network-vr/internal/record"
)

// Config holds sampling parameters. Zero fields take the defaults below.
type Config struct {
	TargetPPS        float64 // records/s budget before k grows (default 50,000)
	MaxK             uint32  // upper bound for k (default 32)
	HeavyHitterPPS   float64 // per-flow record budget (default 200)
	HeavyHitterBurst float64 // token bucket depth (default 10)
	DropAggThreshold int     // drops per tick before aggregation (default 1,000)
	FlowIdle         time.Duration
}

// Defaults returns the documented default configuration.
func Defaults() Config {
	return Config{
		TargetPPS:        50_000,
		MaxK:             32,
		HeavyHitterPPS:   200,
		HeavyHitterBurst: 10,
		DropAggThreshold: 1_000,
		FlowIdle:         2 * time.Second,
	}
}

func (c Config) withDefaults() Config {
	d := Defaults()
	if c.TargetPPS <= 0 {
		c.TargetPPS = d.TargetPPS
	}
	if c.MaxK == 0 {
		c.MaxK = d.MaxK
	}
	if c.HeavyHitterPPS <= 0 {
		c.HeavyHitterPPS = d.HeavyHitterPPS
	}
	if c.HeavyHitterBurst <= 0 {
		c.HeavyHitterBurst = d.HeavyHitterBurst
	}
	if c.DropAggThreshold <= 0 {
		c.DropAggThreshold = d.DropAggThreshold
	}
	if c.FlowIdle <= 0 {
		c.FlowIdle = d.FlowIdle
	}
	return c
}

// K returns ceil(pps/target) clamped to [1, maxK].
func K(pps, target float64, maxK uint32) uint32 {
	if pps <= target || target <= 0 {
		return 1
	}
	k := math.Ceil(pps / target)
	if k > float64(maxK) {
		return maxK
	}
	return uint32(k)
}

// Stats are per-tick counters returned by Flush.
type Stats struct {
	K               uint32  // k used during the tick that was just flushed
	PPS             float64 // measured arrival rate during that tick
	Arrived         uint64  // records offered
	Emitted         uint64  // records returned by Flush
	SampledOut      uint64  // forwarded records rejected by flow sampling
	Throttled       uint64  // records held back by the heavy-hitter bucket
	Drops           uint64  // dropped packets seen
	DropsAggregated bool    // whether this tick's drops were aggregated
	Flows           int     // tracked flows
}

type flowState struct {
	tokens  float64
	lastNs  uint64
	pending uint32 // weight owed to the next emitted record
}

type dropKey struct{ dev, queue, reason uint8 }

// Sampler is not safe for concurrent use; frame.Batcher serialises access.
type Sampler struct {
	cfg     Config
	k       uint32
	flows   map[uint32]*flowState
	out     []record.Record
	drops   []record.Record
	stats   Stats
	latest  uint64
	flushes int
}

// New returns a sampler starting at k = 1.
func New(cfg Config) *Sampler {
	return &Sampler{cfg: cfg.withDefaults(), k: 1, flows: make(map[uint32]*flowState)}
}

// CurrentK is the sampling factor applied to records offered now.
func (s *Sampler) CurrentK() uint32 { return s.k }

// SetK overrides k until the next Flush recomputes it (used by tests).
func (s *Sampler) SetK(k uint32) {
	if k < 1 {
		k = 1
	}
	s.k = k
}

// mix is the murmur3 finalizer; it decorrelates the modulo from weak hashes.
func mix(h uint32) uint32 {
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return h
}

// Keeps reports whether a flow survives sampling at factor k.
func Keeps(flowHash, k uint32) bool { return k <= 1 || mix(flowHash)%k == 0 }

// Offer feeds one raw record (weight is ignored and treated as 1).
func (s *Sampler) Offer(r record.Record) {
	s.stats.Arrived++
	if r.TsNs > s.latest {
		s.latest = r.TsNs
	}
	if r.Dropped() {
		s.stats.Drops++
		r.Weight = 1
		s.drops = append(s.drops, r)
		return
	}
	if !Keeps(r.FlowHash, s.k) {
		s.stats.SampledOut++
		return
	}
	fs := s.flows[r.FlowHash]
	if fs == nil {
		fs = &flowState{tokens: s.cfg.HeavyHitterBurst, lastNs: r.TsNs}
		s.flows[r.FlowHash] = fs
	}
	if r.TsNs > fs.lastNs {
		fs.tokens += float64(r.TsNs-fs.lastNs) / 1e9 * s.cfg.HeavyHitterPPS
		if fs.tokens > s.cfg.HeavyHitterBurst {
			fs.tokens = s.cfg.HeavyHitterBurst
		}
		fs.lastNs = r.TsNs
	}
	owed := fs.pending + s.k
	if fs.tokens < 1 {
		fs.pending = owed
		s.stats.Throttled++
		return
	}
	fs.tokens--
	if owed > math.MaxUint16 {
		fs.pending = owed - math.MaxUint16
		owed = math.MaxUint16
	} else {
		fs.pending = 0
	}
	r.Weight = uint16(owed)
	s.out = append(s.out, r)
}

// Pending returns the weight a flow still owes (throttled, not yet emitted).
func (s *Sampler) Pending(flowHash uint32) uint32 {
	if fs := s.flows[flowHash]; fs != nil {
		return fs.pending
	}
	return 0
}

// Flush ends a tick of length elapsed: it returns the records to send,
// recomputes k from the measured rate and resets per-tick counters.
func (s *Sampler) Flush(elapsed time.Duration) ([]record.Record, Stats) {
	st := s.stats
	st.K = s.k
	if elapsed > 0 {
		st.PPS = float64(st.Arrived) / elapsed.Seconds()
	}
	out := s.out
	if len(s.drops) > s.cfg.DropAggThreshold {
		st.DropsAggregated = true
		out = append(out, aggregate(s.drops)...)
	} else {
		out = append(out, s.drops...)
	}
	st.Emitted = uint64(len(out))

	s.k = K(st.PPS, s.cfg.TargetPPS, s.cfg.MaxK)
	s.flushes++
	if s.flushes%20 == 0 {
		s.gc()
	}
	st.Flows = len(s.flows)

	s.out = make([]record.Record, 0, cap(out))
	s.drops = s.drops[:0]
	s.stats = Stats{}
	return out, st
}

func (s *Sampler) gc() {
	idle := uint64(s.cfg.FlowIdle)
	for h, fs := range s.flows {
		if s.latest > fs.lastNs && s.latest-fs.lastNs > idle {
			delete(s.flows, h)
		}
	}
}

func aggregate(drops []record.Record) []record.Record {
	type acc struct {
		first uint64
		n     uint64
		bytes uint64
	}
	m := make(map[dropKey]*acc)
	var order []dropKey
	for _, d := range drops {
		k := dropKey{d.Dev, d.Queue, d.Reason()}
		a := m[k]
		if a == nil {
			a = &acc{first: d.TsNs}
			m[k] = a
			order = append(order, k)
		}
		a.n++
		a.bytes += uint64(d.PktLen)
	}
	out := make([]record.Record, 0, len(order))
	for _, k := range order {
		a := m[k]
		avgLen := uint16(min(a.bytes/a.n, math.MaxUint16))
		for left := a.n; left > 0; {
			w := min(left, math.MaxUint16)
			left -= w
			out = append(out, record.Record{
				TsNs:    a.first,
				PktLen:  avgLen,
				Dev:     k.dev,
				Queue:   k.queue,
				Verdict: record.VerdictAggregate | k.reason,
				Weight:  uint16(w),
			})
		}
	}
	return out
}
