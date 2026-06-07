package wire4

import (
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/ludomikula/dhcpdbg/internal/attrs"
	"github.com/ludomikula/dhcpdbg/internal/dict"
)

// encodeOptions serialises the option section of a DHCPv4 packet. Options are
// emitted in ascending option-code order — matches the FreeRADIUS encoder so
// the resulting wire bytes round-trip with radclient for the same input. RFC
// 3396 long-option splitting is applied for any single value >255 octets.
func encodeOptions(out []byte, list []attrs.Pair) ([]byte, error) {
	type group struct {
		code uint8
		// data is the concatenated wire-form value (one or more array
		// elements). Each emit of >255 bytes is split per RFC 3396.
		data []byte
	}
	groups := make(map[uint8]*group)
	order := []uint8{}

	for _, p := range list {
		// Decoded-Option-43 is a synthetic alias for the on-wire option 43
		// (Vendor-Specific-Information): the user provides field-by-field
		// content under a vendor namespace and the encoder produces inner
		// 1/1 TLVs. We handle it first because Decoded-Option-43 lives in
		// the FR internal namespace (flagged Internal) and would otherwise
		// be skipped below.
		if p.Attr.Name == "Decoded-Option-43" {
			b, err := encodeDecodedOption43(p.Value)
			if err != nil {
				return nil, fmt.Errorf("Decoded-Option-43: %v", err)
			}
			g, ok := groups[option43Code]
			if !ok {
				g = &group{code: option43Code}
				groups[option43Code] = g
				order = append(order, option43Code)
			}
			g.data = append(g.data, b...)
			continue
		}
		if p.Attr.Internal {
			continue
		}
		// Skip the End option even if user-supplied — Encode adds it.
		if p.Attr.Code == 255 {
			continue
		}
		// Skip Vendor sub-attrs at top level (they're inside option 43).
		if p.Attr.Vendor != 0 {
			continue
		}
		code := uint8(p.Attr.Code)
		b, err := encodeOptionPayload(p)
		if err != nil {
			return nil, fmt.Errorf("attr %s: %v", p.Attr.Name, err)
		}
		g, ok := groups[code]
		if !ok {
			g = &group{code: code}
			groups[code] = g
			order = append(order, code)
		}
		g.data = append(g.data, b...)
	}

	sort.Slice(order, func(i, j int) bool { return order[i] < order[j] })

	for _, c := range order {
		g := groups[c]
		out = emitOption(out, c, g.data)
	}
	return out, nil
}

func emitOption(out []byte, code uint8, data []byte) []byte {
	// RFC 3396: if length >255, split into multiple instances of the same
	// option-code (the receiver concatenates).
	for {
		chunk := len(data)
		if chunk > 255 {
			chunk = 255
		}
		out = append(out, code, byte(chunk))
		out = append(out, data[:chunk]...)
		data = data[chunk:]
		if len(data) == 0 {
			return out
		}
	}
}

// encodeOptionPayload is the per-attribute value-serialisation dispatcher.
// Structured DHCPv4 options (82 Relay-Agent-Information, 124 V-I Vendor
// Class, 125 V-I Vendor-Specific) route through their hand-coded codecs in
// vsa.go / relay.go; everything else falls through to encodeValue's
// primitive path.
func encodeOptionPayload(p attrs.Pair) ([]byte, error) {
	a := p.Attr
	v := p.Value
	switch a.Name {
	case "Relay-Agent-Information":
		if len(v.Group) > 0 {
			return encodeRelayAgentInfo(v)
		}
	case "V-I-Vendor-Class":
		if len(v.Members) > 0 {
			return encodeVIVendorClass(v)
		}
	case "V-I-Vendor-Specific":
		if len(v.Members) > 0 {
			return encodeVIVendorSpecific(v)
		}
	}
	return encodeValue(a, v)
}

func encodeValue(a *dict.Attr, v attrs.Value) ([]byte, error) {
	switch a.Type {
	case dict.TypeUint8, dict.TypeBool:
		return []byte{uint8(v.Uint)}, nil
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
		// Parameter-Request-List style: a single 1-byte option code.
		return []byte{uint8(v.Uint)}, nil
	case dict.TypeString:
		return []byte(v.Str), nil
	case dict.TypeOctets, dict.TypeStruct, dict.TypeTLV, dict.TypeGroup, dict.TypeVSA, dict.TypeUnion:
		return append([]byte(nil), v.Bytes...), nil
	case dict.TypeIPv4Addr:
		if len(v.IPv4) != 4 {
			return nil, fmt.Errorf("bad ipv4 len %d", len(v.IPv4))
		}
		return append([]byte(nil), v.IPv4...), nil
	case dict.TypeIPv6Addr:
		if len(v.IPv6) != 16 {
			return nil, fmt.Errorf("bad ipv6 len %d", len(v.IPv6))
		}
		return append([]byte(nil), v.IPv6...), nil
	case dict.TypeEther:
		return append([]byte(nil), v.Bytes...), nil
	case dict.TypeIfid:
		return append([]byte(nil), v.Bytes...), nil
	case dict.TypeIPv4Prefix, dict.TypeIPv6Prefix:
		// Default wire format: 1 byte prefix length followed by the address.
		// (Some DHCPv4 options have a custom packing — those need bespoke
		// handling, which dhcpdbg defers to opaque octets for now.)
		return append([]byte(nil), v.Bytes...), nil
	}
	return nil, fmt.Errorf("unsupported type %s for %s", a.Type, a.Name)
}

// decodeOption turns a raw option payload into one or more attrs.Pair values
// according to the attribute's dictionary type. For array attributes the
// payload is split into element-sized chunks.
func decodeOption(a *dict.Attr, data []byte) ([]attrs.Pair, error) {
	elemSize := fixedSize(a.Type)
	if a.Flags.Array && elemSize > 0 {
		if len(data)%elemSize != 0 {
			return nil, fmt.Errorf("attr %s: array length %d not a multiple of %d", a.Name, len(data), elemSize)
		}
		out := make([]attrs.Pair, 0, len(data)/elemSize)
		for off := 0; off < len(data); off += elemSize {
			v, err := decodeOne(a, data[off:off+elemSize])
			if err != nil {
				return nil, err
			}
			out = append(out, attrs.Pair{Attr: a, Value: v})
		}
		return out, nil
	}
	v, err := decodeOne(a, data)
	if err != nil {
		return nil, err
	}
	return []attrs.Pair{{Attr: a, Value: v}}, nil
}

func fixedSize(t dict.AttrType) int {
	switch t {
	case dict.TypeUint8, dict.TypeBool, dict.TypeAttribute:
		return 1
	case dict.TypeUint16:
		return 2
	case dict.TypeUint32, dict.TypeDate, dict.TypeTimeDelta, dict.TypeIPv4Addr:
		return 4
	case dict.TypeUint64:
		return 8
	case dict.TypeEther:
		return 6
	case dict.TypeIfid:
		return 8
	case dict.TypeIPv6Addr:
		return 16
	}
	return 0
}

func decodeOne(a *dict.Attr, data []byte) (attrs.Value, error) {
	switch a.Type {
	case dict.TypeUint8, dict.TypeBool, dict.TypeAttribute:
		if len(data) != 1 {
			return attrs.Value{}, fmt.Errorf("attr %s: expected 1 byte, got %d", a.Name, len(data))
		}
		return attrs.Value{Type: a.Type, Uint: uint64(data[0])}, nil
	case dict.TypeUint16:
		if len(data) != 2 {
			return attrs.Value{}, fmt.Errorf("attr %s: expected 2 bytes", a.Name)
		}
		return attrs.Value{Type: a.Type, Uint: uint64(binary.BigEndian.Uint16(data))}, nil
	case dict.TypeUint32, dict.TypeDate, dict.TypeTimeDelta:
		if len(data) != 4 {
			return attrs.Value{}, fmt.Errorf("attr %s: expected 4 bytes", a.Name)
		}
		return attrs.Value{Type: a.Type, Uint: uint64(binary.BigEndian.Uint32(data))}, nil
	case dict.TypeUint64:
		if len(data) != 8 {
			return attrs.Value{}, fmt.Errorf("attr %s: expected 8 bytes", a.Name)
		}
		return attrs.Value{Type: a.Type, Uint: binary.BigEndian.Uint64(data)}, nil
	case dict.TypeString:
		return attrs.Value{Type: dict.TypeString, Str: string(data)}, nil
	case dict.TypeIPv4Addr:
		if len(data) != 4 {
			return attrs.Value{}, fmt.Errorf("attr %s: expected 4 bytes", a.Name)
		}
		return attrs.Value{Type: dict.TypeIPv4Addr, IPv4: append([]byte(nil), data...)}, nil
	case dict.TypeIPv6Addr:
		if len(data) != 16 {
			return attrs.Value{}, fmt.Errorf("attr %s: expected 16 bytes", a.Name)
		}
		return attrs.Value{Type: dict.TypeIPv6Addr, IPv6: append([]byte(nil), data...)}, nil
	case dict.TypeEther:
		return attrs.Value{Type: dict.TypeEther, Bytes: append([]byte(nil), data...)}, nil
	}
	// Default: opaque octets — preserves structured/unknown payloads.
	return attrs.Value{Type: dict.TypeOctets, Bytes: append([]byte(nil), data...)}, nil
}
