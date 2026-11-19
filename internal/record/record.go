// Package record defines the fixed 32-byte packet record shared by the XDP
// program (bpf/xdp.c), the Go agent and the web viewer (web/src/record.js).
//
// Wire layout, little-endian, 32 bytes, every field naturally aligned:
//
//	off  size  field          notes
//	---  ----  -------------  ---------------------------------------------
//	  0     8  ts_ns          capture timestamp in ns (monotonic clock)
//	  8     4  flow_hash      FNV-1a over the 5-tuple, see FlowHash
//	 12     4  src_ip         IPv4 source, raw network-order bytes
//	 16     4  dst_ip         IPv4 destination, raw network-order bytes
//	 20     2  src_port       L4 source port (host order, 0 if not TCP/UDP)
//	 22     2  dst_port       L4 destination port
//	 24     2  pkt_len        L2 frame length in bytes, saturates at 65535
//	 26     1  proto          IP protocol number (6 TCP, 17 UDP, ...)
//	 27     1  dev            agent-local device index
//	 28     1  queue          rx/tx queue index
//	 29     1  verdict        bit 7: aggregated drop record, bits 0-6: drop
//	                          reason (0 = forwarded)
//	 30     2  sample_weight  number of packets this record stands for
//
// The C struct in bpf/xdp.c and the decoder in web/src/record.js must stay
// byte-for-byte identical; testdata/record_golden.json pins both.
package record

import (
	"encoding/binary"
	"errors"
)

// Size is the encoded size of a Record in bytes.
const Size = 32

// Field offsets inside an encoded record.
const (
	OffTsNs     = 0
	OffFlowHash = 8
	OffSrcIP    = 12
	OffDstIP    = 16
	OffSrcPort  = 20
	OffDstPort  = 22
	OffPktLen   = 24
	OffProto    = 26
	OffDev      = 27
	OffQueue    = 28
	OffVerdict  = 29
	OffWeight   = 30
)

// Verdict bits.
const (
	VerdictAggregate  = 0x80 // record summarises many drops of one (dev,queue,reason)
	VerdictReasonMask = 0x7f
)

// Drop reasons (verdict bits 0-6).
const (
	ReasonNone      = 0
	ReasonQueueFull = 1
	ReasonPolicy    = 2
	ReasonNoRoute   = 3
)

// ErrShort is returned when decoding fewer than Size bytes.
var ErrShort = errors.New("record: buffer shorter than 32 bytes")

// Record is the decoded form of one 32-byte packet record.
type Record struct {
	TsNs     uint64
	FlowHash uint32
	SrcIP    [4]byte
	DstIP    [4]byte
	SrcPort  uint16
	DstPort  uint16
	PktLen   uint16
	Proto    uint8
	Dev      uint8
	Queue    uint8
	Verdict  uint8
	Weight   uint16
}

// Dropped reports whether the record describes dropped packets.
func (r Record) Dropped() bool { return r.Verdict&VerdictReasonMask != ReasonNone }

// Reason returns the drop reason (0 when forwarded).
func (r Record) Reason() uint8 { return r.Verdict & VerdictReasonMask }

// Aggregated reports whether the record is a (dev,queue,reason) drop summary.
func (r Record) Aggregated() bool { return r.Verdict&VerdictAggregate != 0 }

// Encode writes r into dst, which must hold at least Size bytes.
func (r Record) Encode(dst []byte) {
	_ = dst[Size-1] // bounds check hint
	le := binary.LittleEndian
	le.PutUint64(dst[OffTsNs:], r.TsNs)
	le.PutUint32(dst[OffFlowHash:], r.FlowHash)
	copy(dst[OffSrcIP:OffSrcIP+4], r.SrcIP[:])
	copy(dst[OffDstIP:OffDstIP+4], r.DstIP[:])
	le.PutUint16(dst[OffSrcPort:], r.SrcPort)
	le.PutUint16(dst[OffDstPort:], r.DstPort)
	le.PutUint16(dst[OffPktLen:], r.PktLen)
	dst[OffProto] = r.Proto
	dst[OffDev] = r.Dev
	dst[OffQueue] = r.Queue
	dst[OffVerdict] = r.Verdict
	le.PutUint16(dst[OffWeight:], r.Weight)
}

// Append appends the encoded record to b.
func (r Record) Append(b []byte) []byte {
	n := len(b)
	b = append(b, make([]byte, Size)...)
	r.Encode(b[n:])
	return b
}

// Decode parses one record from the first Size bytes of src.
func Decode(src []byte) (Record, error) {
	if len(src) < Size {
		return Record{}, ErrShort
	}
	le := binary.LittleEndian
	var r Record
	r.TsNs = le.Uint64(src[OffTsNs:])
	r.FlowHash = le.Uint32(src[OffFlowHash:])
	copy(r.SrcIP[:], src[OffSrcIP:OffSrcIP+4])
	copy(r.DstIP[:], src[OffDstIP:OffDstIP+4])
	r.SrcPort = le.Uint16(src[OffSrcPort:])
	r.DstPort = le.Uint16(src[OffDstPort:])
	r.PktLen = le.Uint16(src[OffPktLen:])
	r.Proto = src[OffProto]
	r.Dev = src[OffDev]
	r.Queue = src[OffQueue]
	r.Verdict = src[OffVerdict]
	r.Weight = le.Uint16(src[OffWeight:])
	return r, nil
}

// DecodeAll parses a concatenation of records. len(src) must be a multiple of Size.
func DecodeAll(src []byte) ([]Record, error) {
	if len(src)%Size != 0 {
		return nil, errors.New("record: length is not a multiple of 32")
	}
	out := make([]Record, 0, len(src)/Size)
	for off := 0; off < len(src); off += Size {
		r, _ := Decode(src[off:])
		out = append(out, r)
	}
	return out, nil
}

// FlowHash is FNV-1a (32-bit) over src_ip(4) | dst_ip(4) | src_port(2, LE) |
// dst_port(2, LE) | proto(1). bpf/xdp.c computes the same value in-kernel.
func FlowHash(src, dst [4]byte, sport, dport uint16, proto uint8) uint32 {
	var key [13]byte
	copy(key[0:4], src[:])
	copy(key[4:8], dst[:])
	binary.LittleEndian.PutUint16(key[8:], sport)
	binary.LittleEndian.PutUint16(key[10:], dport)
	key[12] = proto
	h := uint32(2166136261)
	for _, c := range key {
		h ^= uint32(c)
		h *= 16777619
	}
	return h
}
