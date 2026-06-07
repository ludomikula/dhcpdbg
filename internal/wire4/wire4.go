// Package wire4 encodes and decodes DHCPv4 packets as defined in DHCP-SPEC.md
// Part I and RFC 2131/2132. The encoder/decoder operate on []attrs.Pair lists
// keyed against the DHCPv4 dictionary.
package wire4

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/ludomikula/dhcpdbg/internal/attrs"
	"github.com/ludomikula/dhcpdbg/internal/dict"
)

// Wire codes for the BOOTP-header pseudo-attributes, as declared in
// dictionary.freeradius.internal under `FLAGS internal`. Kept as named
// constants here so the encoder/decoder doesn't grow ad-hoc string lookups.
const (
	hdrOpcode               = 256
	hdrHardwareType         = 257
	hdrHardwareAddressLen   = 258
	hdrHopCount             = 259
	hdrTransactionID        = 260
	hdrNumberOfSeconds      = 261
	hdrFlags                = 262
	hdrClientIPAddress      = 263
	hdrYourIPAddress        = 264
	hdrServerIPAddress      = 265
	hdrGatewayIPAddress     = 266
	hdrClientHardwareAddr   = 267
	hdrServerHostName       = 268
	hdrBootFilename         = 269
	hdrPacketType           = 273
)

// magicCookie is RFC 2131 §3, the 4-byte sentinel after the BOOTP header.
var magicCookie = []byte{0x63, 0x82, 0x53, 0x63}

// Packet is a parsed DHCPv4 packet bundle: its decoded pairs and the raw
// wire bytes (kept for hex-dump / pcap users).
type Packet struct {
	Pairs []attrs.Pair
	Raw   []byte
	// XID is exposed because the request/reply matcher needs it.
	XID uint32
	// MessageType is the DHCP-Message-Type option value (1 = DISCOVER, ...).
	MessageType uint8
}

// Encode serialises a DHCPv4 packet from a Pair list. Op-code derivation:
//   1. If Opcode pseudo-attr (256) is set, use it as-is.
//   2. Else if Packet-Type or Message-Type is one of the client-originated
//      message types (DISCOVER, REQUEST, DECLINE, RELEASE, INFORM), op = 1.
//   3. Else op = 2 (server-message).
//
// Options are emitted sorted by option code (matches the FreeRADIUS encoder
// for byte-compatible output). RFC 3396 long-option split is applied for
// values larger than 255 octets.
func Encode(list []attrs.Pair, proto *dict.Protocol) ([]byte, error) {
	// Pull header pseudo-attrs and options apart.
	hdr := newHeader()
	var options []attrs.Pair
	var msgType uint8
	for _, p := range list {
		if p.Attr.Internal {
			if err := hdr.absorb(p); err != nil {
				return nil, err
			}
			continue
		}
		if p.Attr.Code == 53 { // Message-Type — option-style assignment
			msgType = uint8(p.Value.Uint)
			options = append(options, p)
			continue
		}
		options = append(options, p)
	}

	// If the user supplied a Packet-Type but no Message-Type, mirror it onto
	// the DHCPv4 Message-Type option (53).
	if msgType == 0 && hdr.packetType != 0 {
		msgType = uint8(hdr.packetType)
		if a, ok := proto.AttrByName("Message-Type"); ok {
			// Don't double-add if user already set it.
			has := false
			for _, p := range options {
				if p.Attr == a {
					has = true
					break
				}
			}
			if !has {
				options = append(options, attrs.Pair{Attr: a, Value: attrs.Value{Type: dict.TypeUint8, Uint: uint64(msgType)}})
			}
		}
	}

	if hdr.op == 0 {
		// Heuristic per RFC 2131 §4.1 & dictionary.freeradius.internal.
		switch msgType {
		case 1, 3, 4, 7, 8: // DISCOVER, REQUEST, DECLINE, RELEASE, INFORM
			hdr.op = 1
		default:
			hdr.op = 2
		}
	}
	if hdr.htype == 0 {
		hdr.htype = 1 // Ethernet
	}
	if hdr.hlen == 0 {
		hdr.hlen = 6
	}

	buf := make([]byte, 0, 576)
	buf = hdr.marshal(buf)
	buf = append(buf, magicCookie...)
	var err error
	buf, err = encodeOptions(buf, options)
	if err != nil {
		return nil, err
	}
	// End option (255). RFC 2131 §3 also recommends padding to 300 octets so
	// some servers / relays don't choke; matches FreeRADIUS behaviour.
	buf = append(buf, 0xff)
	for len(buf) < 300 {
		buf = append(buf, 0x00)
	}
	return buf, nil
}

// Decode parses a DHCPv4 packet into a Pair list keyed against proto. It
// surfaces the BOOTP-header fields as pseudo-attrs (the "internal" namespace)
// so output round-trips back through Encode.
func Decode(raw []byte, proto *dict.Protocol) (*Packet, error) {
	if len(raw) < 240 {
		return nil, fmt.Errorf("dhcpv4: short packet (%d octets)", len(raw))
	}
	if !equalBytes(raw[236:240], magicCookie) {
		return nil, errors.New("dhcpv4: bad magic cookie")
	}

	pkt := &Packet{Raw: raw}
	pkt.XID = binary.BigEndian.Uint32(raw[4:8])

	addInternal := func(code uint32, v attrs.Value) {
		if a, ok := proto.AttrByCode(code); ok {
			pkt.Pairs = append(pkt.Pairs, attrs.Pair{Attr: a, Value: v})
		}
	}

	addInternal(hdrOpcode, attrs.Value{Type: dict.TypeUint8, Uint: uint64(raw[0])})
	addInternal(hdrHardwareType, attrs.Value{Type: dict.TypeUint8, Uint: uint64(raw[1])})
	addInternal(hdrHardwareAddressLen, attrs.Value{Type: dict.TypeUint8, Uint: uint64(raw[2])})
	addInternal(hdrHopCount, attrs.Value{Type: dict.TypeUint8, Uint: uint64(raw[3])})
	addInternal(hdrTransactionID, attrs.Value{Type: dict.TypeUint32, Uint: uint64(pkt.XID)})
	addInternal(hdrNumberOfSeconds, attrs.Value{Type: dict.TypeUint16, Uint: uint64(binary.BigEndian.Uint16(raw[8:10]))})
	addInternal(hdrFlags, attrs.Value{Type: dict.TypeUint16, Uint: uint64(binary.BigEndian.Uint16(raw[10:12]))})
	addInternal(hdrClientIPAddress, attrs.Value{Type: dict.TypeIPv4Addr, IPv4: append([]byte(nil), raw[12:16]...)})
	addInternal(hdrYourIPAddress, attrs.Value{Type: dict.TypeIPv4Addr, IPv4: append([]byte(nil), raw[16:20]...)})
	addInternal(hdrServerIPAddress, attrs.Value{Type: dict.TypeIPv4Addr, IPv4: append([]byte(nil), raw[20:24]...)})
	addInternal(hdrGatewayIPAddress, attrs.Value{Type: dict.TypeIPv4Addr, IPv4: append([]byte(nil), raw[24:28]...)})

	hlen := int(raw[2])
	if hlen > 16 {
		hlen = 16
	}
	chaddr := append([]byte(nil), raw[28:28+hlen]...)
	addInternal(hdrClientHardwareAddr, attrs.Value{Type: dict.TypeEther, Bytes: chaddr})

	// sname (64) and file (128) are optional strings.
	if s := trimNul(raw[44:108]); s != "" {
		addInternal(hdrServerHostName, attrs.Value{Type: dict.TypeString, Str: s})
	}
	if s := trimNul(raw[108:236]); s != "" {
		addInternal(hdrBootFilename, attrs.Value{Type: dict.TypeString, Str: s})
	}

	// Options: code(1) + len(1) + value.
	i := 240
	type acc struct {
		code uint8
		data []byte
	}
	var accs []acc
	for i < len(raw) {
		c := raw[i]
		if c == 0 { // pad
			i++
			continue
		}
		if c == 255 { // end
			break
		}
		if i+1 >= len(raw) {
			break
		}
		l := int(raw[i+1])
		if i+2+l > len(raw) {
			return nil, fmt.Errorf("dhcpv4: option %d truncated", c)
		}
		// RFC 3396 concat: same code seen again concatenates.
		merged := false
		for j := range accs {
			if accs[j].code == c {
				accs[j].data = append(accs[j].data, raw[i+2:i+2+l]...)
				merged = true
				break
			}
		}
		if !merged {
			accs = append(accs, acc{code: c, data: append([]byte(nil), raw[i+2:i+2+l]...)})
		}
		i += 2 + l
	}

	for _, a := range accs {
		if a.code == 53 && len(a.data) >= 1 {
			pkt.MessageType = a.data[0]
		}
		da, ok := proto.AttrByCode(uint32(a.code))
		if !ok {
			// Unknown option — fall back to a synthetic octets attr name.
			pkt.Pairs = append(pkt.Pairs, attrs.Pair{
				Attr:  syntheticUnknown(uint32(a.code)),
				Value: attrs.Value{Type: dict.TypeOctets, Bytes: a.data},
			})
			continue
		}
		// Structured DHCPv4 options: hand-coded decoders feed back into
		// the dotted-form printer, so listen-mode output round-trips
		// through ReadList.
		switch da.Name {
		case "Relay-Agent-Information":
			v, err := decodeRelayAgentInfo(da, a.data, proto)
			if err != nil {
				return nil, err
			}
			pkt.Pairs = append(pkt.Pairs, attrs.Pair{Attr: da, Value: v})
			continue
		case "V-I-Vendor-Class":
			pairs, err := decodeVIVendorClass(a.data, proto)
			if err != nil {
				return nil, err
			}
			pkt.Pairs = append(pkt.Pairs, pairs...)
			continue
		case "V-I-Vendor-Specific":
			pairs, err := decodeVIVendorSpecific(a.data, proto)
			if err != nil {
				return nil, err
			}
			pkt.Pairs = append(pkt.Pairs, pairs...)
			continue
		}
		vs, err := decodeOption(da, a.data)
		if err != nil {
			return nil, err
		}
		pkt.Pairs = append(pkt.Pairs, vs...)
	}
	return pkt, nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func trimNul(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func syntheticUnknown(code uint32) *dict.Attr {
	return &dict.Attr{
		Name: fmt.Sprintf("DHCP-Option-%d", code),
		Code: code,
		Type: dict.TypeOctets,
	}
}
