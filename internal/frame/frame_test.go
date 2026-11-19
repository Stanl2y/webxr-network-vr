package frame

import (
	"testing"
	"time"

	"github.com/vmihailenco/msgpack/v5"

	"github.com/Stanl2y/webxr-network-vr/internal/record"
	"github.com/Stanl2y/webxr-network-vr/internal/sampler"
)

func TestBuildEncodeDecode(t *testing.T) {
	recs := []record.Record{
		{TsNs: 500, FlowHash: 1, Weight: 1},
		{TsNs: 300, FlowHash: 2, Weight: 2, Verdict: record.ReasonQueueFull},
	}
	f := Build(DefaultInterval, recs)
	f.DroppedTicks = 3
	b, err := Encode(f)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.TickMs != 50 || got.BaseTsNs != 300 || got.Count != 2 || got.DroppedTicks != 3 {
		t.Fatalf("header mismatch: %+v", got)
	}
	out, err := record.DecodeAll(got.Records)
	if err != nil || out[1] != recs[1] {
		t.Fatalf("records mismatch: %v %+v", err, out)
	}
}

func TestWireKeys(t *testing.T) {
	b, _ := Encode(Build(DefaultInterval, []record.Record{{TsNs: 9}}))
	var m map[string]any
	if err := msgpack.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"tick_ms", "base_ts_ns", "count", "dropped_ticks", "records"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing key %q in %v", k, m)
		}
	}
	if len(m) != 5 {
		t.Errorf("want 5 keys, got %d", len(m))
	}
	if _, ok := m["records"].([]byte); !ok {
		t.Errorf("records must be msgpack bin, got %T", m["records"])
	}
}

func TestDecodeRejectsBadCount(t *testing.T) {
	b, _ := Encode(Frame{Count: 2, Records: make([]byte, 32)})
	if _, err := Decode(b); err == nil {
		t.Fatal("want count/length error")
	}
}

func TestEmptyFrame(t *testing.T) {
	f := Build(DefaultInterval, nil)
	if f.Count != 0 || f.BaseTsNs != 0 || len(f.Records) != 0 {
		t.Fatalf("empty frame: %+v", f)
	}
}

func TestBatcherTickAndMissedTicks(t *testing.T) {
	b := NewBatcher(sampler.New(sampler.Config{}), 0)
	t0 := time.Unix(0, 0)
	b.Tick(t0)
	for i := 0; i < 10; i++ {
		b.Add(record.Record{TsNs: uint64(i), FlowHash: uint32(i)})
	}
	f, st := b.Tick(t0.Add(50 * time.Millisecond))
	if f.Count != 10 || f.DroppedTicks != 0 || st.Arrived != 10 {
		t.Fatalf("tick 1: count=%d dropped=%d arrived=%d", f.Count, f.DroppedTicks, st.Arrived)
	}
	// Next tick arrives 200 ms late -> 3 missed ticks.
	f, _ = b.Tick(t0.Add(250 * time.Millisecond))
	if f.DroppedTicks != 3 {
		t.Fatalf("dropped_ticks = %d, want 3", f.DroppedTicks)
	}
}
