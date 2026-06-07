// Package pcap reads DHCPv4/DHCPv6 packets out of libpcap or pcapng
// capture files. It transparently auto-detects the file format from the
// first 4 magic bytes and surfaces a stream of decoded UDP datagrams via
// Reader.Next.
//
// The reader is link-layer-aware (Ethernet+VLAN, Linux SLL/SLL2, raw IP),
// parses IPv4 / IPv6 headers including the common IPv6 extension chain,
// then narrows the stream to packets on the four standard DHCP ports
// (67/68 for v4, 546/547 for v6). Anything else is skipped silently so
// piping a noisy `tcpdump` stream is harmless.
package pcap

import (
	"net"
	"time"
)

// Family is the auto-detected DHCP protocol family for a Frame, picked
// from the UDP source/destination ports. FamilyUnknown is reserved for
// future use — current Reader.Next only emits Frames with V4 or V6.
type Family int

const (
	FamilyUnknown Family = 0
	FamilyV4      Family = 4
	FamilyV6      Family = 6
)

// String returns the user-facing label used in text output ("DHCPv4",
// "DHCPv6", or "unknown").
func (f Family) String() string {
	switch f {
	case FamilyV4:
		return "DHCPv4"
	case FamilyV6:
		return "DHCPv6"
	}
	return "unknown"
}

// Frame is one DHCP UDP datagram pulled from a capture, with the IP
// endpoints and timestamp recovered from the surrounding headers.
type Frame struct {
	// Timestamp is the per-record timestamp from the capture, in UTC.
	// The CLI's --timestamp flag controls how it's rendered.
	Timestamp time.Time

	// Family is V4 for ports 67/68, V6 for ports 546/547.
	Family Family

	// SrcIP/DstIP are the parsed IP-header endpoints. For IPv6 they are
	// 16-byte net.IPs; for IPv4 they are 4-byte net.IPs (use To4 if you
	// want a consistent length).
	SrcIP, DstIP net.IP
	// SrcPort/DstPort are the UDP-header ports.
	SrcPort, DstPort uint16

	// Payload is the UDP payload — i.e. the raw DHCP wire bytes. The
	// caller hands this verbatim to wire4.Decode or wire6.Decode.
	Payload []byte

	// Caplen / Origlen are the captured and original packet lengths from
	// the pcap per-record header. They include all link-layer headers,
	// so they aren't directly comparable to len(Payload).
	Caplen  int
	Origlen int

	// Truncated is true when the capture snaplen cut the original packet
	// short. The Payload may still parse if only trailing options were
	// dropped, but the caller is expected to flag this in output.
	Truncated bool
}

// Reader is the streaming pcap / pcapng reader surface. NewReader
// auto-detects the format; concrete implementations live in classic.go
// and pcapng.go.
type Reader interface {
	// Next returns the next DHCP Frame, or (nil, io.EOF) at end of
	// stream. Non-DHCP packets are skipped internally; the caller only
	// ever sees Frames worth decoding.
	//
	// Frame-level errors (truncated record, unsupported link type for
	// THIS frame, IP-parse failure, fragmented IPv6) are returned to the
	// caller so it can log-and-continue. The reader itself stays usable.
	Next() (*Frame, error)
}

// Common link-layer types we accept. Values are from the libpcap LINKTYPE
// registry (see https://www.tcpdump.org/linktypes.html).
const (
	linkTypeEthernet = 1
	linkTypeRaw      = 101 // raw IPv4 or IPv6
	linkTypeLinuxSLL = 113
	linkTypeLinuxSLL2 = 276
)

// DHCP UDP port numbers from RFC 2131 / RFC 8415.
const (
	dhcpv4ServerPort = 67
	dhcpv4ClientPort = 68
	dhcpv6ClientPort = 546
	dhcpv6ServerPort = 547
)

// isDHCPv4Port / isDHCPv6Port classify a UDP port. A datagram is a DHCP
// candidate when either of its src/dst ports is one of these.
func isDHCPv4Port(p uint16) bool { return p == dhcpv4ServerPort || p == dhcpv4ClientPort }
func isDHCPv6Port(p uint16) bool { return p == dhcpv6ClientPort || p == dhcpv6ServerPort }

// familyForPorts picks the Family from the (src, dst) pair. Returns
// FamilyUnknown if neither port is a DHCP port.
func familyForPorts(src, dst uint16) Family {
	if isDHCPv4Port(src) || isDHCPv4Port(dst) {
		return FamilyV4
	}
	if isDHCPv6Port(src) || isDHCPv6Port(dst) {
		return FamilyV6
	}
	return FamilyUnknown
}
