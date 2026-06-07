package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// --------------------------------------------------------------- fixtures

// buildDHCPv4Discover returns a minimal DHCPv4 DISCOVER payload (240 bytes
// header + a Message-Type option + an End option). Enough for the
// reader to classify it as DHCPv4; the wire4.Decode tests cover full
// validation.
func buildDHCPv4Discover() []byte {
	pkt := make([]byte, 240)
	pkt[0] = 1 // op = BOOTREQUEST
	pkt[1] = 1 // htype = Ethernet
	pkt[2] = 6 // hlen
	binary.BigEndian.PutUint32(pkt[4:8], 0xdeadbeef) // XID
	// chaddr (16 bytes from offset 28)
	copy(pkt[28:34], []byte{2, 0, 0, 0, 0, 1})
	// magic cookie
	pkt[236], pkt[237], pkt[238], pkt[239] = 0x63, 0x82, 0x53, 0x63
	// options: 53 (Message-Type) = 1 (Discover), 255 (End)
	pkt = append(pkt, 53, 1, 1, 0xff)
	return pkt
}

// buildDHCPv6Solicit returns a minimal DHCPv6 SOLICIT payload (4-byte
// header — message-type + 3-byte tx-id — and zero options, which is
// not a valid solicit but enough for the reader to surface it).
func buildDHCPv6Solicit() []byte {
	return []byte{
		0x01,           // msg-type = SOLICIT
		0x12, 0x34, 0x56, // transaction-id
	}
}

// wrapEthernetIPv4UDP wraps payload in Ethernet (no VLAN) + IPv4 + UDP
// frames suitable for a libpcap LINKTYPE_ETHERNET record.
func wrapEthernetIPv4UDP(srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	udp := wrapUDP(srcPort, dstPort, payload)
	ipv4 := wrapIPv4(srcIP, dstIP, udp)
	eth := make([]byte, 14)
	// dst MAC (broadcast), src MAC (lab), ethertype = 0x0800 (IPv4)
	copy(eth[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(eth[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
	binary.BigEndian.PutUint16(eth[12:14], 0x0800)
	return append(eth, ipv4...)
}

// wrapEthernetVLANIPv4UDP is like wrapEthernetIPv4UDP but inserts a single
// 802.1Q VLAN tag (vid=42) between the MAC pair and the ethertype.
func wrapEthernetVLANIPv4UDP(srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	udp := wrapUDP(srcPort, dstPort, payload)
	ipv4 := wrapIPv4(srcIP, dstIP, udp)
	eth := make([]byte, 18) // 14 + 4-byte tag
	copy(eth[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(eth[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
	binary.BigEndian.PutUint16(eth[12:14], 0x8100) // VLAN TPID
	binary.BigEndian.PutUint16(eth[14:16], 42)     // VID 42 (PCP 0, DEI 0)
	binary.BigEndian.PutUint16(eth[16:18], 0x0800) // inner ethertype
	return append(eth, ipv4...)
}

// wrapLinuxSLLIPv6UDP wraps payload in SLL + IPv6 + UDP frames suitable
// for a libpcap LINKTYPE_LINUX_SLL record.
func wrapLinuxSLLIPv6UDP(srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	udp := wrapUDP(srcPort, dstPort, payload)
	ipv6 := wrapIPv6(srcIP, dstIP, udp)
	sll := make([]byte, 16)
	binary.BigEndian.PutUint16(sll[14:16], 0x86dd) // L3 protocol = IPv6
	return append(sll, ipv6...)
}

// wrapUDP / wrapIPv4 / wrapIPv6 emit minimal headers — only the fields
// the reader actually consumes are filled in. Checksums are zero
// because the reader ignores them.
func wrapUDP(src, dst uint16, payload []byte) []byte {
	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:2], src)
	binary.BigEndian.PutUint16(udp[2:4], dst)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))
	// checksum stays zero
	copy(udp[8:], payload)
	return udp
}

func wrapIPv4(src, dst net.IP, payload []byte) []byte {
	ip := make([]byte, 20)
	ip[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(payload)))
	ip[8] = 64       // TTL
	ip[9] = protoUDP // UDP
	copy(ip[12:16], src.To4())
	copy(ip[16:20], dst.To4())
	return append(ip, payload...)
}

func wrapIPv6(src, dst net.IP, payload []byte) []byte {
	ip := make([]byte, 40)
	ip[0] = 0x60 // version 6
	binary.BigEndian.PutUint16(ip[4:6], uint16(len(payload)))
	ip[6] = protoUDP // next header
	ip[7] = 64       // hop limit
	copy(ip[8:24], src.To16())
	copy(ip[24:40], dst.To16())
	return append(ip, payload...)
}

// buildClassicPcap returns a complete classic-pcap file with one
// recordEntry per provided frame.
type recordEntry struct {
	frame   []byte
	caplen  int // override caplen for truncation tests; 0 = len(frame)
	origlen int // override origlen; 0 = len(frame)
	ts      time.Time
}

func buildClassicPcap(linkType int, bo binary.ByteOrder, records []recordEntry) []byte {
	var buf bytes.Buffer
	hdr := make([]byte, 24)
	bo.PutUint32(hdr[0:4], 0xa1b2c3d4)
	bo.PutUint16(hdr[4:6], 2)
	bo.PutUint16(hdr[6:8], 4)
	bo.PutUint32(hdr[16:20], 65535)
	bo.PutUint32(hdr[20:24], uint32(linkType))
	buf.Write(hdr)
	for _, r := range records {
		ts := r.ts
		if ts.IsZero() {
			ts = time.Unix(1717_000_000, 123_456_000).UTC()
		}
		caplen := r.caplen
		if caplen == 0 {
			caplen = len(r.frame)
		}
		origlen := r.origlen
		if origlen == 0 {
			origlen = len(r.frame)
		}
		rec := make([]byte, 16)
		bo.PutUint32(rec[0:4], uint32(ts.Unix()))
		bo.PutUint32(rec[4:8], uint32(ts.Nanosecond()/1000))
		bo.PutUint32(rec[8:12], uint32(caplen))
		bo.PutUint32(rec[12:16], uint32(origlen))
		buf.Write(rec)
		buf.Write(r.frame[:caplen])
	}
	return buf.Bytes()
}

// buildPcapngSingle returns a tiny pcapng file containing one SHB, one
// IDB (linkType), and one EPB carrying frame.
func buildPcapngSingle(linkType int, frame []byte) []byte {
	bo := binary.LittleEndian
	var buf bytes.Buffer

	// SHB: block type, block length, byte-order magic, ver-major,
	// ver-minor, section length (= -1), trailing length.
	shb := make([]byte, 28)
	bo.PutUint32(shb[0:4], blockSHB)
	bo.PutUint32(shb[4:8], 28)
	bo.PutUint32(shb[8:12], 0x1A2B3C4D)
	bo.PutUint16(shb[12:14], 1) // major
	bo.PutUint16(shb[14:16], 0) // minor
	// section length: int64 = -1
	for i := 16; i < 24; i++ {
		shb[i] = 0xff
	}
	bo.PutUint32(shb[24:28], 28)
	buf.Write(shb)

	// IDB
	idb := make([]byte, 20)
	bo.PutUint32(idb[0:4], blockIDB)
	bo.PutUint32(idb[4:8], 20)
	bo.PutUint16(idb[8:10], uint16(linkType))
	// reserved
	bo.PutUint32(idb[12:16], 65535) // snaplen
	bo.PutUint32(idb[16:20], 20)
	buf.Write(idb)

	// EPB: 28-byte header (type+len+iface+tsHi+tsLo+caplen+origlen) +
	// packet data (caplen, padded to 4-byte boundary) + 4-byte trailing
	// length. No options.
	caplen := len(frame)
	padded := (caplen + 3) &^ 3
	pad := padded - caplen
	epbLen := 28 + padded + 4
	epb := make([]byte, 28, epbLen)
	bo.PutUint32(epb[0:4], blockEPB)
	bo.PutUint32(epb[4:8], uint32(epbLen))
	bo.PutUint32(epb[8:12], 0)           // interface ID
	bo.PutUint32(epb[12:16], 0x00060ab5) // ts hi (arbitrary)
	bo.PutUint32(epb[16:20], 0x40000000) // ts lo
	bo.PutUint32(epb[20:24], uint32(caplen))
	bo.PutUint32(epb[24:28], uint32(caplen))
	epb = append(epb, frame...)
	for i := 0; i < pad; i++ {
		epb = append(epb, 0)
	}
	t := make([]byte, 4)
	bo.PutUint32(t[0:4], uint32(epbLen))
	epb = append(epb, t...)
	buf.Write(epb)

	return buf.Bytes()
}

// --------------------------------------------------------------- tests

// TestEthernetIPv4DHCPDiscover builds a one-packet classic-pcap file
// (Ethernet + IPv4 + UDP + DHCPDISCOVER) and verifies the reader pulls
// it back out as a Frame with the right ports and family.
func TestEthernetIPv4DHCPDiscover(t *testing.T) {
	dhcp := buildDHCPv4Discover()
	frame := wrapEthernetIPv4UDP(net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), 68, 67, dhcp)
	data := buildClassicPcap(linkTypeEthernet, binary.LittleEndian, []recordEntry{{frame: frame}})

	r, err := NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	f, err := r.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if f.Family != FamilyV4 {
		t.Fatalf("family = %v, want V4", f.Family)
	}
	if f.SrcPort != 68 || f.DstPort != 67 {
		t.Fatalf("ports = %d → %d, want 68 → 67", f.SrcPort, f.DstPort)
	}
	if !bytes.Equal(f.Payload, dhcp) {
		t.Fatalf("payload mismatch (%d vs %d bytes)", len(f.Payload), len(dhcp))
	}
	// Next call → EOF.
	if _, err := r.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF, got %v", err)
	}
}

// TestVLANTaggedEthernet checks that an 802.1Q-tagged frame still decodes
// — the link layer follows VLAN tags transparently.
func TestVLANTaggedEthernet(t *testing.T) {
	dhcp := buildDHCPv4Discover()
	frame := wrapEthernetVLANIPv4UDP(net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), 68, 67, dhcp)
	data := buildClassicPcap(linkTypeEthernet, binary.LittleEndian, []recordEntry{{frame: frame}})

	r, err := NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	f, err := r.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if f.Family != FamilyV4 {
		t.Fatalf("family = %v, want V4 (VLAN-tagged)", f.Family)
	}
}

// TestLinuxSLLIPv6DHCPv6Solicit covers the SLL + IPv6 + UDP path used
// for traces captured against the loopback / any interface on Linux.
func TestLinuxSLLIPv6DHCPv6Solicit(t *testing.T) {
	dhcp := buildDHCPv6Solicit()
	frame := wrapLinuxSLLIPv6UDP(
		net.ParseIP("fe80::1"), net.ParseIP("ff02::1:2"), 546, 547, dhcp,
	)
	data := buildClassicPcap(linkTypeLinuxSLL, binary.LittleEndian, []recordEntry{{frame: frame}})

	r, err := NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	f, err := r.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if f.Family != FamilyV6 {
		t.Fatalf("family = %v, want V6", f.Family)
	}
	if f.SrcPort != 546 || f.DstPort != 547 {
		t.Fatalf("ports = %d → %d, want 546 → 547", f.SrcPort, f.DstPort)
	}
}

// TestNonDHCPSkipped confirms the reader walks past non-DHCP UDP frames
// (DNS on UDP/53) without surfacing them.
func TestNonDHCPSkipped(t *testing.T) {
	dns := wrapEthernetIPv4UDP(net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), 50000, 53, []byte("query"))
	dhcp := wrapEthernetIPv4UDP(net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), 68, 67, buildDHCPv4Discover())
	data := buildClassicPcap(linkTypeEthernet, binary.LittleEndian,
		[]recordEntry{{frame: dns}, {frame: dhcp}})

	r, err := NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	f, err := r.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if f.Family != FamilyV4 {
		t.Fatalf("got non-DHCP packet through filter")
	}
	if _, err := r.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF, got %v", err)
	}
}

// TestTruncatedFlag uses an explicit caplen < origlen on the record.
func TestTruncatedFlag(t *testing.T) {
	dhcp := buildDHCPv4Discover()
	frame := wrapEthernetIPv4UDP(net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), 68, 67, dhcp)
	data := buildClassicPcap(linkTypeEthernet, binary.LittleEndian, []recordEntry{
		{frame: frame, caplen: len(frame) - 10, origlen: len(frame)},
	})
	r, err := NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	f, err := r.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if !f.Truncated {
		t.Fatalf("expected Truncated=true (caplen %d, origlen %d)", f.Caplen, f.Origlen)
	}
}

// TestBigEndianMagic round-trips a big-endian classic pcap to confirm the
// magic-byte sniff promotes the right byte order.
func TestBigEndianMagic(t *testing.T) {
	dhcp := buildDHCPv4Discover()
	frame := wrapEthernetIPv4UDP(net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), 68, 67, dhcp)
	data := buildClassicPcap(linkTypeEthernet, binary.BigEndian, []recordEntry{{frame: frame}})

	r, err := NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	f, err := r.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if f.Family != FamilyV4 {
		t.Fatalf("big-endian capture decoded as %v", f.Family)
	}
}

// TestBadMagic feeds garbage and verifies the format-detect path errors
// out with a useful message instead of silently misparsing.
func TestBadMagic(t *testing.T) {
	_, err := NewReader(bytes.NewReader([]byte{0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0}))
	if err == nil {
		t.Fatal("expected error for bad magic, got nil")
	}
}

// TestPcapngSingle covers the pcapng SHB+IDB+EPB happy path: one
// DHCPDISCOVER inside an Ethernet+IPv4 frame.
func TestPcapngSingle(t *testing.T) {
	dhcp := buildDHCPv4Discover()
	frame := wrapEthernetIPv4UDP(net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), 68, 67, dhcp)
	data := buildPcapngSingle(linkTypeEthernet, frame)

	r, err := NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("NewReader (pcapng): %v", err)
	}
	f, err := r.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if f.Family != FamilyV4 || f.SrcPort != 68 || f.DstPort != 67 {
		t.Fatalf("decoded frame mismatch: %+v", f)
	}
	if _, err := r.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF, got %v", err)
	}
}

// TestUnsupportedLinkTypeIsSurfaced — frames in an unsupported link type
// produce a per-packet error (not EOF) so the CLI can log + continue.
func TestUnsupportedLinkTypeIsSurfaced(t *testing.T) {
	data := buildClassicPcap(7, binary.LittleEndian, []recordEntry{
		{frame: []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}}, // link 7 = ARCNET (unsupported)
	})
	r, err := NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	_, err = r.Next()
	if err == nil {
		t.Fatal("expected per-packet error for unsupported link type")
	}
}
