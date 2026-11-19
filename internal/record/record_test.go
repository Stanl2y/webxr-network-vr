package record

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"testing"
)

type goldenRecord struct {
	TsNs     uint64 `json:"ts_ns,string"`
	FlowHash uint32 `json:"flow_hash"`
	SrcIP    string `json:"src_ip"`
	DstIP    string `json:"dst_ip"`
	SrcPort  uint16 `json:"src_port"`
	DstPort  uint16 `json:"dst_port"`
	PktLen   uint16 `json:"pkt_len"`
	Proto    uint8  `json:"proto"`
	Dev      uint8  `json:"dev"`
	Queue    uint8  `json:"queue"`
	Verdict  uint8  `json:"verdict"`
	Weight   uint16 `json:"sample_weight"`
}

type golden struct {
	Name   string       `json:"name"`
	Hex    string       `json:"hex"`
	Record goldenRecord `json:"record"`
}

func loadGolden(t *testing.T) []golden {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/record_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var g []golden
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	if len(g) == 0 {
		t.Fatal("no golden vectors")
	}
	return g
}

func (g goldenRecord) toRecord(t *testing.T) Record {
	t.Helper()
	return Record{
		TsNs: g.TsNs, FlowHash: g.FlowHash,
		SrcIP: netip.MustParseAddr(g.SrcIP).As4(), DstIP: netip.MustParseAddr(g.DstIP).As4(),
		SrcPort: g.SrcPort, DstPort: g.DstPort, PktLen: g.PktLen, Proto: g.Proto,
		Dev: g.Dev, Queue: g.Queue, Verdict: g.Verdict, Weight: g.Weight,
	}
}

func TestGoldenEncode(t *testing.T) {
	for _, g := range loadGolden(t) {
		t.Run(g.Name, func(t *testing.T) {
			want, err := hex.DecodeString(g.Hex)
			if err != nil {
				t.Fatal(err)
			}
			if len(want) != Size {
				t.Fatalf("golden hex is %d bytes, want %d", len(want), Size)
			}
			got := make([]byte, Size)
			g.Record.toRecord(t).Encode(got)
			if !bytes.Equal(got, want) {
				t.Fatalf("encode mismatch\n got %x\nwant %x", got, want)
			}
		})
	}
}

func TestGoldenDecode(t *testing.T) {
	for _, g := range loadGolden(t) {
		t.Run(g.Name, func(t *testing.T) {
			raw, _ := hex.DecodeString(g.Hex)
			got, err := Decode(raw)
			if err != nil {
				t.Fatal(err)
			}
			if want := g.Record.toRecord(t); got != want {
				t.Fatalf("decode mismatch\n got %+v\nwant %+v", got, want)
			}
		})
	}
}

func TestFieldOffsets(t *testing.T) {
	// Each field written alone must land at its documented offset.
	r := Record{Weight: 0xBEEF}
	b := make([]byte, Size)
	r.Encode(b)
	if b[OffWeight] != 0xEF || b[OffWeight+1] != 0xBE {
		t.Fatalf("weight not little-endian at offset %d: %x", OffWeight, b)
	}
	if OffWeight+2 != Size {
		t.Fatalf("layout does not end at %d", Size)
	}
}

func TestVerdictHelpers(t *testing.T) {
	r := Record{Verdict: VerdictAggregate | ReasonPolicy}
	if !r.Dropped() || !r.Aggregated() || r.Reason() != ReasonPolicy {
		t.Fatalf("helpers wrong for %#x", r.Verdict)
	}
	if (Record{}).Dropped() {
		t.Fatal("zero record must be forwarded")
	}
}

func TestDecodeErrors(t *testing.T) {
	if _, err := Decode(make([]byte, Size-1)); err != ErrShort {
		t.Fatalf("want ErrShort, got %v", err)
	}
	if _, err := DecodeAll(make([]byte, Size+1)); err == nil {
		t.Fatal("want error for ragged buffer")
	}
}

func TestAppendDecodeAll(t *testing.T) {
	var buf []byte
	in := []Record{{TsNs: 1, Weight: 1}, {TsNs: 2, Queue: 5, Weight: 7}}
	for _, r := range in {
		buf = r.Append(buf)
	}
	out, err := DecodeAll(buf)
	if err != nil || len(out) != 2 || out[1] != in[1] {
		t.Fatalf("round trip failed: %v %+v", err, out)
	}
}

func TestFlowHashKnownValue(t *testing.T) {
	// FNV-1a over 13 zero bytes; pins the key layout used by bpf/xdp.c.
	if got := FlowHash([4]byte{}, [4]byte{}, 0, 0, 0); got != 0xda0f62ef {
		t.Fatalf("FlowHash(zero) = %#x", got)
	}
	a := FlowHash([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 1234, 80, 6)
	b := FlowHash([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 1}, 80, 1234, 6)
	if a == b {
		t.Fatal("hash should be direction-sensitive")
	}
}
