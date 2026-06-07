package pcap

import (
	"encoding/binary"
	"fmt"
)

// stripLink consumes the link-layer header at the head of frame, returning
// (ethertype, payload, error). The ethertype is the L3 protocol number:
//
//	0x0800 = IPv4
//	0x86dd = IPv6
//
// Any other ethertype causes a "not IP" error so the caller can skip the
// frame. Unsupported link types are also an error.
//
// VLAN tags (0x8100 and 0x88a8 — the QinQ stacked form) are followed
// through, so single-tagged and double-tagged Ethernet frames decode the
// same as untagged ones.
func stripLink(linkType int, frame []byte) (uint16, []byte, error) {
	switch linkType {
	case linkTypeEthernet:
		return stripEthernet(frame)
	case linkTypeLinuxSLL:
		return stripLinuxSLL(frame)
	case linkTypeLinuxSLL2:
		return stripLinuxSLL2(frame)
	case linkTypeRaw:
		// Raw IP: no link-layer header, but we need to pick the
		// ethertype from the IP version nibble.
		if len(frame) < 1 {
			return 0, nil, fmt.Errorf("raw: empty frame")
		}
		switch frame[0] >> 4 {
		case 4:
			return 0x0800, frame, nil
		case 6:
			return 0x86dd, frame, nil
		}
		return 0, nil, fmt.Errorf("raw: bad IP version nibble 0x%02x", frame[0])
	default:
		return 0, nil, fmt.Errorf("unsupported link type %d", linkType)
	}
}

// stripEthernet handles the classic 14-byte Ethernet II header plus any
// 802.1Q / 802.1ad VLAN tags that follow. The L3 ethertype is whatever
// remains after the tag chain.
func stripEthernet(frame []byte) (uint16, []byte, error) {
	if len(frame) < 14 {
		return 0, nil, fmt.Errorf("ethernet: short header (%d bytes)", len(frame))
	}
	off := 12 // skip src + dst MAC
	et := binary.BigEndian.Uint16(frame[off : off+2])
	off += 2
	// Follow up to 2 stacked VLAN tags (QinQ).
	for i := 0; i < 2; i++ {
		if et != 0x8100 && et != 0x88a8 {
			break
		}
		if off+4 > len(frame) {
			return 0, nil, fmt.Errorf("ethernet: truncated VLAN tag")
		}
		// 2 bytes TCI, then 2 bytes inner ethertype.
		off += 2
		et = binary.BigEndian.Uint16(frame[off : off+2])
		off += 2
	}
	return et, frame[off:], nil
}

// stripLinuxSLL handles Linux "cooked" v1 captures (linktype 113, 16-byte
// header). The L3 protocol number lives in the 14th–15th bytes.
func stripLinuxSLL(frame []byte) (uint16, []byte, error) {
	const hdrLen = 16
	if len(frame) < hdrLen {
		return 0, nil, fmt.Errorf("linux-sll: short header (%d bytes)", len(frame))
	}
	et := binary.BigEndian.Uint16(frame[14:16])
	return et, frame[hdrLen:], nil
}

// stripLinuxSLL2 handles Linux "cooked" v2 captures (linktype 276,
// 20-byte header). The L3 protocol number is the first 2 bytes.
func stripLinuxSLL2(frame []byte) (uint16, []byte, error) {
	const hdrLen = 20
	if len(frame) < hdrLen {
		return 0, nil, fmt.Errorf("linux-sll2: short header (%d bytes)", len(frame))
	}
	et := binary.BigEndian.Uint16(frame[0:2])
	return et, frame[hdrLen:], nil
}
