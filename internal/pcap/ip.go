package pcap

import (
	"encoding/binary"
	"fmt"
	"net"
)

// Per RFC 5237 / IANA, the protocol number for UDP.
const protoUDP = 17

// stripIPv4 parses an IPv4 header, returning (proto, src, dst, payload).
// Honours the IHL field for option length. Refuses fragmented packets
// (anything with MF set or a non-zero offset).
func stripIPv4(frame []byte) (uint8, net.IP, net.IP, []byte, error) {
	if len(frame) < 20 {
		return 0, nil, nil, nil, fmt.Errorf("ipv4: short header (%d bytes)", len(frame))
	}
	verIHL := frame[0]
	if verIHL>>4 != 4 {
		return 0, nil, nil, nil, fmt.Errorf("ipv4: not an IPv4 header (version=%d)", verIHL>>4)
	}
	ihl := int(verIHL&0x0f) * 4
	if ihl < 20 || ihl > len(frame) {
		return 0, nil, nil, nil, fmt.Errorf("ipv4: bad IHL %d", ihl)
	}
	totalLen := int(binary.BigEndian.Uint16(frame[2:4]))
	if totalLen < ihl || totalLen > len(frame) {
		// Tolerate a totalLen larger than the slice when capture was
		// truncated — clamp to what we have so the caller still sees
		// the option bytes that DID land in the file.
		totalLen = len(frame)
	}
	fragField := binary.BigEndian.Uint16(frame[6:8])
	if fragField&0x1fff != 0 || fragField&0x2000 != 0 {
		// Non-zero fragment offset OR More-Fragments bit set.
		return 0, nil, nil, nil, fmt.Errorf("ipv4: fragmented packet (offset=%d, MF=%v)",
			fragField&0x1fff, fragField&0x2000 != 0)
	}
	proto := frame[9]
	src := net.IP(frame[12:16])
	dst := net.IP(frame[16:20])
	return proto, src, dst, frame[ihl:totalLen], nil
}

// IPv6 next-header values we walk through transparently. See RFC 8200.
const (
	ipv6HBH     = 0  // Hop-by-Hop Options
	ipv6Routing = 43 // Routing
	ipv6Frag    = 44 // Fragment
	ipv6DestOpt = 60 // Destination Options
)

// stripIPv6 parses an IPv6 header chain, returning (proto, src, dst,
// payload). The proto is the next-header value after walking the
// extension-header chain. Fragmented packets (Fragment header with a
// non-zero offset, or with More=true) are refused — they can't be safely
// reassembled here.
func stripIPv6(frame []byte) (uint8, net.IP, net.IP, []byte, error) {
	const fixedHdr = 40
	if len(frame) < fixedHdr {
		return 0, nil, nil, nil, fmt.Errorf("ipv6: short header (%d bytes)", len(frame))
	}
	if frame[0]>>4 != 6 {
		return 0, nil, nil, nil, fmt.Errorf("ipv6: not an IPv6 header (version=%d)", frame[0]>>4)
	}
	payloadLen := int(binary.BigEndian.Uint16(frame[4:6]))
	next := frame[6]
	src := net.IP(frame[8:24])
	dst := net.IP(frame[24:40])

	body := frame[fixedHdr:]
	if payloadLen <= len(body) {
		body = body[:payloadLen]
	}
	// Walk extension headers.
	for {
		switch next {
		case ipv6HBH, ipv6Routing, ipv6DestOpt:
			if len(body) < 2 {
				return 0, nil, nil, nil, fmt.Errorf("ipv6: truncated ext header")
			}
			next = body[0]
			hdrLen := (int(body[1]) + 1) * 8 // length in 8-octet units, excluding first 8
			if hdrLen > len(body) {
				return 0, nil, nil, nil, fmt.Errorf("ipv6: ext header overruns payload")
			}
			body = body[hdrLen:]
		case ipv6Frag:
			if len(body) < 8 {
				return 0, nil, nil, nil, fmt.Errorf("ipv6: truncated fragment header")
			}
			fragOff := binary.BigEndian.Uint16(body[2:4])
			more := fragOff&0x1 != 0
			off := fragOff >> 3
			if off != 0 || more {
				return 0, nil, nil, nil, fmt.Errorf("ipv6: fragmented packet (offset=%d, M=%v)", off, more)
			}
			next = body[0]
			body = body[8:]
		default:
			return next, src, dst, body, nil
		}
	}
}
