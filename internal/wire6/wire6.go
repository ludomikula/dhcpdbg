// Package wire6 encodes and decodes DHCPv6 packets (RFC 8415) as scoped in
// DHCP-SPEC.md Part II. Header is 4 octets (msg-type + 24-bit txn-id), then
// options as code(2)+len(2)+value. Nested options (IA-NA → IA-Addr → status,
// IA-PD → IA-Prefix → status, Vendor-Opts, Relay-Message) are represented
// recursively by the dictionary's "group" type. For attributes typed as
// "struct" (Client-ID, Server-ID, ...) dhcpdbg treats the value as opaque
// octets — the user supplies the encoded form directly. See DHCP-SPEC.md
// §II.2 for the encoding rules.
package wire6

import (
	"fmt"

	"github.com/ludomikula/dhcpdbg/internal/attrs"
	"github.com/ludomikula/dhcpdbg/internal/dict"
)

// DHCPv6 internal pseudo-attrs from dictionary.freeradius.internal (DHCPv6).
const (
	hdrPacketType    = 65536
	hdrTransactionID = 65537
)

// Packet is a parsed DHCPv6 packet bundle.
type Packet struct {
	Pairs       []attrs.Pair
	Raw         []byte
	MessageType uint8
	TxnID       uint32 // low 24 bits used
}

// Encode serialises a DHCPv6 packet. The first pair that's a Packet-Type sets
// the message-type byte; Transaction-ID (3 octets, big-endian) is taken from
// the corresponding pseudo-attr or generated random by the caller.
func Encode(list []attrs.Pair, proto *dict.Protocol) ([]byte, error) {
	var msgType uint8
	var txn uint32
	var options []attrs.Pair
	for _, p := range list {
		if p.Attr.Internal {
			switch p.Attr.Code {
			case hdrPacketType:
				msgType = uint8(p.Value.Uint)
			case hdrTransactionID:
				if len(p.Value.Bytes) >= 3 {
					txn = uint32(p.Value.Bytes[0])<<16 | uint32(p.Value.Bytes[1])<<8 | uint32(p.Value.Bytes[2])
				} else {
					txn = uint32(p.Value.Uint) & 0xffffff
				}
			}
			continue
		}
		options = append(options, p)
	}
	if msgType == 0 {
		return nil, fmt.Errorf("dhcpv6: missing Packet-Type (or pass --type)")
	}

	buf := make([]byte, 4, 256)
	buf[0] = msgType
	buf[1] = byte(txn >> 16)
	buf[2] = byte(txn >> 8)
	buf[3] = byte(txn)

	var err error
	buf, err = encodeOptions(buf, options, proto)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

// Decode parses a DHCPv6 packet into pairs keyed against proto. The 24-bit
// transaction ID is surfaced as a 3-byte octets value (matches the
// FreeRADIUS internal dictionary, which marks Transaction-ID as 3-octet
// octets).
func Decode(raw []byte, proto *dict.Protocol) (*Packet, error) {
	if len(raw) < 4 {
		return nil, fmt.Errorf("dhcpv6: short packet (%d octets)", len(raw))
	}
	pkt := &Packet{Raw: raw, MessageType: raw[0]}
	pkt.TxnID = uint32(raw[1])<<16 | uint32(raw[2])<<8 | uint32(raw[3])

	if a, ok := proto.AttrByCode(hdrPacketType); ok {
		pkt.Pairs = append(pkt.Pairs, attrs.Pair{Attr: a, Value: attrs.Value{Type: dict.TypeUint32, Uint: uint64(raw[0])}})
	}
	if a, ok := proto.AttrByCode(hdrTransactionID); ok {
		pkt.Pairs = append(pkt.Pairs, attrs.Pair{Attr: a, Value: attrs.Value{Type: dict.TypeOctets, Bytes: append([]byte(nil), raw[1:4]...)}})
	}

	pairs, err := decodeOptions(raw[4:], proto)
	if err != nil {
		return nil, err
	}
	pkt.Pairs = append(pkt.Pairs, pairs...)
	return pkt, nil
}
