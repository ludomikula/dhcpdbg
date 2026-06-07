package pcap

import (
	"errors"
	"fmt"
	"net"
	"time"
)

// errSkip is returned by frameFromBytes when the record is not a DHCP
// candidate (wrong link type, non-IP ethertype, non-UDP IP proto,
// non-DHCP UDP ports). Readers treat this as "advance silently"; non-
// errSkip errors are surfaced to the caller so they can be logged.
var errSkip = errors.New("skip")

// frameFromBytes takes one raw captured frame (link-layer through the
// rest) and reduces it to a Frame, returning errSkip when the packet is
// not DHCP and not worth surfacing. linkType is the pcap LINKTYPE for
// the file (per-frame in pcapng — interface-specific).
func frameFromBytes(linkType int, captured []byte, origLen int, ts time.Time) (*Frame, error) {
	ethertype, l3, err := stripLink(linkType, captured)
	if err != nil {
		return nil, fmt.Errorf("link: %v", err)
	}

	var ipProto uint8
	var src, dst net.IP
	var udpBody []byte
	switch ethertype {
	case 0x0800:
		var perr error
		ipProto, src, dst, udpBody, perr = stripIPv4(l3)
		if perr != nil {
			return nil, fmt.Errorf("ipv4: %v", perr)
		}
	case 0x86dd:
		var perr error
		ipProto, src, dst, udpBody, perr = stripIPv6(l3)
		if perr != nil {
			return nil, fmt.Errorf("ipv6: %v", perr)
		}
	default:
		// Not IP — definitely not DHCP. Skip without noise.
		return nil, errSkip
	}
	if ipProto != protoUDP {
		return nil, errSkip
	}
	srcPort, dstPort, payload, err := stripUDP(udpBody)
	if err != nil {
		return nil, fmt.Errorf("udp: %v", err)
	}
	fam := familyForPorts(srcPort, dstPort)
	if fam == FamilyUnknown {
		// Non-DHCP UDP. Skip silently.
		return nil, errSkip
	}
	return &Frame{
		Timestamp: ts,
		Family:    fam,
		SrcIP:     src,
		DstIP:     dst,
		SrcPort:   srcPort,
		DstPort:   dstPort,
		Payload:   payload,
		Caplen:    len(captured),
		Origlen:   origLen,
		Truncated: len(captured) < origLen,
	}, nil
}
