package wire6

import (
	"encoding/binary"
	"fmt"

	"github.com/ludomikula/dhcpdbg/internal/attrs"
	"github.com/ludomikula/dhcpdbg/internal/dict"
)

// encodeOptions packs a flat list of options. Each option is code(2)+len(2)+value
// in network byte order (RFC 8415 §11.1). Repeated attributes that the
// dictionary marks `array` (e.g. Option-Request) are concatenated into a
// single option payload — that's how DHCPv6 ORO is on the wire (RFC 8415
// §21.7). Struct, group, vsa, and union container types route through the
// structured codec (struct.go, vsa.go, duid.go) so IA-NA, IA-Addr, IA-PD,
// IA-PD-Prefix, Status-Code, Vendor-Class, Vendor-Opts, Client-ID, and
// Server-ID all get field-by-field encoding from dotted-form input.
func encodeOptions(out []byte, list []attrs.Pair, proto *dict.Protocol) ([]byte, error) {
	type group struct {
		code uint16
		buf  []byte
	}
	groups := make(map[uint16]*group)
	order := []uint16{}
	for _, p := range list {
		if p.Attr.Code > 0xffff {
			continue
		}
		b, err := encodeOptionValue(p)
		if err != nil {
			return nil, fmt.Errorf("attr %s: %v", p.Attr.Name, err)
		}
		code := uint16(p.Attr.Code)
		g, ok := groups[code]
		if !ok {
			g = &group{code: code}
			groups[code] = g
			order = append(order, code)
		}
		if !p.Attr.Flags.Array && len(g.buf) > 0 {
			// Non-array repeated — keep the last assignment (matches FR
			// behaviour for top-level options that aren't arrays).
			g.buf = b
			continue
		}
		g.buf = append(g.buf, b...)
	}
	for _, code := range order {
		g := groups[code]
		if len(g.buf) > 0xffff {
			return nil, fmt.Errorf("attr %d: value too long for DHCPv6 option (%d bytes)", code, len(g.buf))
		}
		out = append(out,
			byte(code>>8), byte(code),
			byte(len(g.buf)>>8), byte(len(g.buf)))
		out = append(out, g.buf...)
	}
	return out, nil
}

// decodeOptions walks the option section of a DHCPv6 packet. Structured
// container types (struct, group, vsa, union) route through the structured
// decoder so output round-trips back through the dotted-form parser.
// Unknown option codes become DHCPv6-Option-<n> with octets value.
func decodeOptions(data []byte, proto *dict.Protocol) ([]attrs.Pair, error) {
	var out []attrs.Pair
	i := 0
	for i+4 <= len(data) {
		code := binary.BigEndian.Uint16(data[i : i+2])
		l := int(binary.BigEndian.Uint16(data[i+2 : i+4]))
		if i+4+l > len(data) {
			return nil, fmt.Errorf("dhcpv6 option %d truncated", code)
		}
		payload := data[i+4 : i+4+l]
		da, ok := proto.AttrByCode(uint32(code))
		if !ok {
			out = append(out, attrs.Pair{
				Attr:  syntheticUnknown(uint32(code)),
				Value: attrs.Value{Type: dict.TypeOctets, Bytes: append([]byte(nil), payload...)},
			})
			i += 4 + l
			continue
		}
		v, err := decodeOptionPayload(da, payload, proto)
		if err != nil {
			return nil, err
		}
		out = append(out, attrs.Pair{Attr: da, Value: v})
		i += 4 + l
	}
	return out, nil
}

// decodeOptionPayload dispatches to the right structured decoder for an
// attribute's type, falling back to the per-value primitive decoder.
func decodeOptionPayload(a *dict.Attr, data []byte, proto *dict.Protocol) (attrs.Value, error) {
	switch a.Name {
	case "Client-ID", "Server-ID":
		return decodeDUID(a, data), nil
	case "Vendor-Opts":
		return decodeVendorOpts(data, proto)
	}
	switch a.Type {
	case dict.TypeStruct, dict.TypeUnion:
		if len(a.Members) > 0 {
			return decodeStructValue(a, data, proto)
		}
		return attrs.Value{Type: dict.TypeOctets, Bytes: append([]byte(nil), data...)}, nil
	case dict.TypeGroup:
		pairs, err := decodeOptions(data, proto)
		if err != nil {
			return attrs.Value{}, err
		}
		return attrs.Value{Type: dict.TypeGroup, Group: pairs}, nil
	case dict.TypeVSA:
		return decodeVendorOpts(data, proto)
	}
	return decodeOne6(a, data)
}

func encodeValue6(a *dict.Attr, v attrs.Value) ([]byte, error) {
	switch a.Type {
	case dict.TypeUint8, dict.TypeBool:
		return []byte{byte(v.Uint)}, nil
	case dict.TypeUint16:
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], uint16(v.Uint))
		return b[:], nil
	case dict.TypeUint32, dict.TypeDate, dict.TypeTimeDelta:
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(v.Uint))
		return b[:], nil
	case dict.TypeUint64:
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], v.Uint)
		return b[:], nil
	case dict.TypeAttribute:
		// Option-Request entries are 2 bytes each in DHCPv6.
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], uint16(v.Uint))
		return b[:], nil
	case dict.TypeString:
		return []byte(v.Str), nil
	case dict.TypeIPv6Addr:
		if len(v.IPv6) != 16 {
			return nil, fmt.Errorf("bad ipv6 length %d", len(v.IPv6))
		}
		return append([]byte(nil), v.IPv6...), nil
	case dict.TypeIPv4Addr:
		return append([]byte(nil), v.IPv4...), nil
	}
	// All container types fall through as opaque octets — the user supplied
	// the encoded blob.
	return append([]byte(nil), v.Bytes...), nil
}

func decodeOne6(a *dict.Attr, data []byte) (attrs.Value, error) {
	switch a.Type {
	case dict.TypeUint8, dict.TypeBool:
		if len(data) < 1 {
			return attrs.Value{}, fmt.Errorf("attr %s: empty", a.Name)
		}
		return attrs.Value{Type: a.Type, Uint: uint64(data[0])}, nil
	case dict.TypeUint16:
		if len(data) < 2 {
			return attrs.Value{}, fmt.Errorf("attr %s: short", a.Name)
		}
		return attrs.Value{Type: a.Type, Uint: uint64(binary.BigEndian.Uint16(data))}, nil
	case dict.TypeUint32, dict.TypeDate, dict.TypeTimeDelta:
		if len(data) < 4 {
			return attrs.Value{}, fmt.Errorf("attr %s: short", a.Name)
		}
		return attrs.Value{Type: a.Type, Uint: uint64(binary.BigEndian.Uint32(data))}, nil
	case dict.TypeString:
		return attrs.Value{Type: dict.TypeString, Str: string(data)}, nil
	case dict.TypeIPv6Addr:
		if len(data) != 16 {
			return attrs.Value{}, fmt.Errorf("attr %s: expected 16 bytes", a.Name)
		}
		return attrs.Value{Type: dict.TypeIPv6Addr, IPv6: append([]byte(nil), data...)}, nil
	}
	return attrs.Value{Type: dict.TypeOctets, Bytes: append([]byte(nil), data...)}, nil
}

func syntheticUnknown(code uint32) *dict.Attr {
	return &dict.Attr{
		Name: fmt.Sprintf("DHCPv6-Option-%d", code),
		Code: code,
		Type: dict.TypeOctets,
	}
}
