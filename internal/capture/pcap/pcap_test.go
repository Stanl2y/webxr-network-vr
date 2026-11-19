//go:build pcap

package pcap

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/Stanl2y/webxr-network-vr/internal/record"
)

func frame(t *testing.T, l4 gopacket.SerializableLayer, proto layers.IPProtocol) []byte {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: proto, SrcIP: net.IPv4(10, 0, 0, 1), DstIP: net.IPv4(10, 0, 0, 2)}
	if n, ok := l4.(interface {
		SetNetworkLayerForChecksum(gopacket.NetworkLayer) error
	}); ok {
		_ = n.SetNetworkLayerForChecksum(ip)
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, l4, gopacket.Payload([]byte("hello"))); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestReplayParsesTCPAndUDP(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	pkts := [][]byte{
		frame(t, &layers.TCP{SrcPort: 40000, DstPort: 443, SYN: true}, layers.IPProtocolTCP),
		frame(t, &layers.UDP{SrcPort: 5353, DstPort: 53}, layers.IPProtocolUDP),
	}
	ts := time.Unix(1700000000, 0)
	for i, p := range pkts {
		ci := gopacket.CaptureInfo{Timestamp: ts.Add(time.Duration(i) * time.Millisecond), CaptureLength: len(p), Length: len(p)}
		if err := w.WritePacket(ci, p); err != nil {
			t.Fatal(err)
		}
	}
	f.Close()

	var got []record.Record
	n, err := Replay(context.Background(), path, 3, false, func(r record.Record) { got = append(got, r) })
	if err != nil || n != 2 {
		t.Fatalf("Replay: n=%d err=%v", n, err)
	}
	tcp, udp := got[0], got[1]
	if tcp.Proto != 6 || tcp.SrcPort != 40000 || tcp.DstPort != 443 || tcp.Dev != 3 {
		t.Fatalf("tcp record wrong: %+v", tcp)
	}
	if udp.Proto != 17 || udp.DstPort != 53 || udp.SrcIP != [4]byte{10, 0, 0, 1} {
		t.Fatalf("udp record wrong: %+v", udp)
	}
	if tcp.FlowHash != record.FlowHash(tcp.SrcIP, tcp.DstIP, 40000, 443, 6) {
		t.Fatal("flow hash mismatch")
	}
	if udp.TsNs-tcp.TsNs != uint64(time.Millisecond) {
		t.Fatalf("timestamps not preserved: %d", udp.TsNs-tcp.TsNs)
	}
}
