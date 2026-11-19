// Package frame batches sampled records into 20 Hz MessagePack frames.
//
// A frame is a MessagePack map with five keys:
//
//	tick_ms       uint32  tick length in ms (50 at 20 Hz)
//	base_ts_ns    uint64  smallest ts_ns in the frame (0 if empty)
//	count         uint32  number of records
//	dropped_ticks uint32  ticks not delivered to this client since its last
//	                      frame (slow consumer or a late producer tick)
//	records       bin     count * 32 bytes, see package record
package frame

import (
	"errors"
	"sync"
	"time"

	"github.com/vmihailenco/msgpack/v5"

	"github.com/Stanl2y/webxr-network-vr/internal/record"
	"github.com/Stanl2y/webxr-network-vr/internal/sampler"
)

// DefaultInterval is the 20 Hz tick.
const DefaultInterval = 50 * time.Millisecond

// Frame is one tick of sampled records.
type Frame struct {
	TickMs       uint32 `msgpack:"tick_ms"`
	BaseTsNs     uint64 `msgpack:"base_ts_ns"`
	Count        uint32 `msgpack:"count"`
	DroppedTicks uint32 `msgpack:"dropped_ticks"`
	Records      []byte `msgpack:"records"`
}

// Build packs records into a frame.
func Build(tick time.Duration, recs []record.Record) Frame {
	f := Frame{TickMs: uint32(tick / time.Millisecond), Count: uint32(len(recs))}
	f.Records = make([]byte, 0, len(recs)*record.Size)
	for i, r := range recs {
		if i == 0 || r.TsNs < f.BaseTsNs {
			f.BaseTsNs = r.TsNs
		}
		f.Records = r.Append(f.Records)
	}
	return f
}

// Encode serialises f as MessagePack.
func Encode(f Frame) ([]byte, error) { return msgpack.Marshal(&f) }

// Decode parses a MessagePack frame and checks its record payload size.
func Decode(b []byte) (Frame, error) {
	var f Frame
	if err := msgpack.Unmarshal(b, &f); err != nil {
		return Frame{}, err
	}
	if len(f.Records) != int(f.Count)*record.Size {
		return Frame{}, errors.New("frame: records length does not match count")
	}
	return f, nil
}

// Batcher collects records from capture goroutines and emits one frame per tick.
type Batcher struct {
	mu       sync.Mutex
	s        *sampler.Sampler
	interval time.Duration
	last     time.Time
}

// NewBatcher wraps a sampler. interval <= 0 means DefaultInterval.
func NewBatcher(s *sampler.Sampler, interval time.Duration) *Batcher {
	if interval <= 0 {
		interval = DefaultInterval
	}
	return &Batcher{s: s, interval: interval}
}

// Add offers one raw record; safe for concurrent use.
func (b *Batcher) Add(r record.Record) {
	b.mu.Lock()
	b.s.Offer(r)
	b.mu.Unlock()
}

// Tick flushes the sampler at time now and builds the frame. When the
// previous tick was more than 1.5 intervals ago the missed ticks are
// reported in DroppedTicks.
func (b *Batcher) Tick(now time.Time) (Frame, sampler.Stats) {
	b.mu.Lock()
	elapsed := b.interval
	var missed uint32
	if !b.last.IsZero() {
		elapsed = now.Sub(b.last)
		if elapsed > b.interval*3/2 {
			missed = uint32(elapsed/b.interval) - 1
		}
	}
	b.last = now
	recs, st := b.s.Flush(elapsed)
	b.mu.Unlock()

	f := Build(b.interval, recs)
	f.DroppedTicks = missed
	return f, st
}

// Run ticks until done is closed, passing each frame to sink.
func (b *Batcher) Run(done <-chan struct{}, sink func(Frame, sampler.Stats)) {
	t := time.NewTicker(b.interval)
	defer t.Stop()
	b.Tick(time.Now()) // establish the baseline
	for {
		select {
		case <-done:
			return
		case now := <-t.C:
			f, st := b.Tick(now)
			sink(f, st)
		}
	}
}
