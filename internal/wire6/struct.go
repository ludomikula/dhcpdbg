package wire6

import (
	"encoding/binary"
	"fmt"

	"github.com/ludomikula/dhcpdbg/internal/attrs"
	"github.com/ludomikula/dhcpdbg/internal/dict"
)

// encodeStructValue writes a struct-typed Value: each MEMBER in declared
// order, concatenated. Members of type group recurse into encodeGroup.
// Members not present in the Value are emitted as their type's zero —
// matches the FreeRADIUS encoder for missing fields.
func encodeStructValue(a *dict.Attr, v attrs.Value) ([]byte, error) {
	if len(a.Members) == 0 {
		// Unknown / opaque struct — keep the explicit bytes the user passed.
		return append([]byte(nil), v.Bytes...), nil
	}
	out := make([]byte, 0, 32)
	for _, m := range a.Members {
		mv := v.MemberByName(m.Name)
		var sub attrs.Value
		if mv != nil {
			sub = mv.Value
		} else {
			sub = attrs.Value{Type: m.Type}
		}
		b, err := encodeMember(m, sub)
		if err != nil {
			return nil, fmt.Errorf("%s.%s: %v", a.Name, m.Name, err)
		}
		out = append(out, b...)
	}
	return out, nil
}

// encodeMember serialises one member's value. Container members (group)
// recurse; scalars hit encodeScalar. Members with a length prefix wrap
// each element in a length tag (User-Class / Vendor-Class.Data style).
func encodeMember(m *dict.Member, v attrs.Value) ([]byte, error) {
	switch m.Type {
	case dict.TypeGroup:
		return encodeGroupOptions(v.Group)
	case dict.TypeStruct:
		// Nested struct inside a struct: serialise its sub-MEMBERs.
		// For the DUID variants this branch carries the inner Ethernet
		// struct; the encoder walks v.Members directly using a synthesised
		// member-list when needed.
		return concatStructMembers(v)
	}
	if m.Array && m.LengthPrefix > 0 {
		return encodeLengthPrefixedArray(m, v)
	}
	return encodeScalar(m.Type, v, m.FixedSize)
}

// encodeGroupOptions emits a sequence of DHCPv6 options (code(2)+len(2)+value)
// for the nested option list of a group-typed value.
func encodeGroupOptions(pairs []attrs.Pair) ([]byte, error) {
	out := make([]byte, 0, 32)
	for _, p := range pairs {
		if p.Attr == nil {
			continue
		}
		val, err := encodeOptionValue(p)
		if err != nil {
			return nil, err
		}
		if len(val) > 0xffff {
			return nil, fmt.Errorf("nested option %s: value too long (%d bytes)", p.Attr.Name, len(val))
		}
		hdr := []byte{
			byte(p.Attr.Code >> 8), byte(p.Attr.Code),
			byte(len(val) >> 8), byte(len(val)),
		}
		out = append(out, hdr...)
		out = append(out, val...)
	}
	return out, nil
}

// encodeOptionValue is the per-Pair value-serialisation dispatcher for any
// DHCPv6 option (top-level or nested). Mirrors encodeValue6 in options.go
// but goes through encodeStructValue / encodeVSA / encodeDUID for the
// container types so this entry point is recursion-safe.
func encodeOptionValue(p attrs.Pair) ([]byte, error) {
	a := p.Attr
	v := p.Value
	// Hand-coded codecs by attribute name.
	switch a.Name {
	case "Client-ID", "Server-ID":
		return encodeDUID(v)
	case "Vendor-Opts":
		return encodeVendorOpts(v)
	}
	switch a.Type {
	case dict.TypeStruct, dict.TypeUnion:
		return encodeStructValue(a, v)
	case dict.TypeGroup:
		return encodeGroupOptions(v.Group)
	case dict.TypeVSA:
		return encodeVendorOpts(v)
	}
	return encodeScalar(a.Type, v, 0)
}

// concatStructMembers writes the MEMBERs already attached to v in their
// stored order. Used by inner struct values that don't carry a dict.Attr.
func concatStructMembers(v attrs.Value) ([]byte, error) {
	out := make([]byte, 0, 16)
	for _, mv := range v.Members {
		b, err := encodeMember(mv.Member, mv.Value)
		if err != nil {
			return nil, err
		}
		out = append(out, b...)
	}
	return out, nil
}

// encodeLengthPrefixedArray packs an array whose MEMBER carries
// `length=uint16,array` — used for User-Class.Value and Vendor-Class.Data.
// Each element is preceded by a 2-byte length. For a single-value
// (non-array) MEMBER with length=uint16, we still emit one length-prefixed
// element.
func encodeLengthPrefixedArray(m *dict.Member, v attrs.Value) ([]byte, error) {
	elem, err := encodeScalar(m.Type, v, 0)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 2+len(elem))
	switch m.LengthPrefix {
	case 8:
		out = append(out, byte(len(elem)))
	case 16:
		out = append(out, byte(len(elem)>>8), byte(len(elem)))
	default:
		return nil, fmt.Errorf("unsupported length prefix %d", m.LengthPrefix)
	}
	out = append(out, elem...)
	return out, nil
}

// encodeScalar serialises one primitive value, sized by AttrType. If
// fixedSize is non-zero the value is zero-padded / truncated to that many
// bytes (used for `octets[N]` MEMBERs like Auth.Information).
func encodeScalar(t dict.AttrType, v attrs.Value, fixedSize int) ([]byte, error) {
	switch t {
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
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], uint16(v.Uint))
		return b[:], nil
	case dict.TypeString:
		return []byte(v.Str), nil
	case dict.TypeIPv6Addr:
		if len(v.IPv6) != 16 {
			return nil, fmt.Errorf("ipv6: bad length %d", len(v.IPv6))
		}
		return append([]byte(nil), v.IPv6...), nil
	case dict.TypeIPv4Addr:
		return append([]byte(nil), v.IPv4...), nil
	case dict.TypeIPv6Prefix:
		// Wire form for an IPv6 prefix in DHCPv6 structs (IA-PD-Prefix):
		// 1-byte length then full 16-byte address. Value.Bytes carries
		// `[len, addr...]` exactly as parsed.
		return append([]byte(nil), v.Bytes...), nil
	case dict.TypeEther:
		return append([]byte(nil), v.Bytes...), nil
	case dict.TypeIfid:
		return append([]byte(nil), v.Bytes...), nil
	case dict.TypeOctets:
		out := append([]byte(nil), v.Bytes...)
		if fixedSize > 0 {
			if len(out) < fixedSize {
				out = append(out, make([]byte, fixedSize-len(out))...)
			} else if len(out) > fixedSize {
				out = out[:fixedSize]
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("unsupported member type %s", t)
}

// decodeStructValue reverses encodeStructValue: walks MEMBERs and consumes
// data piece by piece. A trailing variable-length member (octets/string/group)
// soaks up the remainder.
func decodeStructValue(a *dict.Attr, data []byte, proto *dict.Protocol) (attrs.Value, error) {
	out := attrs.Value{Type: dict.TypeStruct}
	cur := data
	for i, m := range a.Members {
		last := i == len(a.Members)-1
		val, rest, err := decodeMember(m, cur, proto, last)
		if err != nil {
			return out, err
		}
		out.Members = append(out.Members, attrs.MemberValue{Member: m, Value: val})
		cur = rest
	}
	return out, nil
}

func decodeMember(m *dict.Member, data []byte, proto *dict.Protocol, last bool) (attrs.Value, []byte, error) {
	switch m.Type {
	case dict.TypeGroup:
		pairs, err := decodeOptions(data, proto)
		if err != nil {
			return attrs.Value{}, nil, err
		}
		return attrs.Value{Type: dict.TypeGroup, Group: pairs}, nil, nil
	}
	size := scalarSize(m.Type)
	if m.FixedSize > 0 {
		size = m.FixedSize
	}
	if last && (m.Type == dict.TypeOctets || m.Type == dict.TypeString) && size == 0 {
		size = len(data)
	}
	if size > len(data) {
		return attrs.Value{}, nil, fmt.Errorf("member %s: short read (need %d, have %d)", m.Name, size, len(data))
	}
	v, err := decodeScalar(m.Type, data[:size])
	if err != nil {
		return attrs.Value{}, nil, err
	}
	return v, data[size:], nil
}

func scalarSize(t dict.AttrType) int {
	switch t {
	case dict.TypeUint8, dict.TypeBool, dict.TypeAttribute:
		return 1
	case dict.TypeUint16:
		return 2
	case dict.TypeUint32, dict.TypeDate, dict.TypeTimeDelta, dict.TypeIPv4Addr:
		return 4
	case dict.TypeUint64:
		return 8
	case dict.TypeIPv6Addr:
		return 16
	case dict.TypeEther:
		return 6
	case dict.TypeIfid:
		return 8
	case dict.TypeIPv6Prefix:
		return 17 // 1-byte len + 16-byte addr (IA-PD-Prefix wire layout)
	}
	return 0
}

func decodeScalar(t dict.AttrType, data []byte) (attrs.Value, error) {
	switch t {
	case dict.TypeUint8, dict.TypeBool:
		return attrs.Value{Type: t, Uint: uint64(data[0])}, nil
	case dict.TypeUint16:
		return attrs.Value{Type: t, Uint: uint64(binary.BigEndian.Uint16(data))}, nil
	case dict.TypeUint32, dict.TypeDate, dict.TypeTimeDelta:
		return attrs.Value{Type: t, Uint: uint64(binary.BigEndian.Uint32(data))}, nil
	case dict.TypeUint64:
		return attrs.Value{Type: t, Uint: binary.BigEndian.Uint64(data)}, nil
	case dict.TypeAttribute:
		return attrs.Value{Type: t, Uint: uint64(data[0])}, nil
	case dict.TypeIPv4Addr:
		return attrs.Value{Type: t, IPv4: append([]byte(nil), data...)}, nil
	case dict.TypeIPv6Addr:
		return attrs.Value{Type: t, IPv6: append([]byte(nil), data...)}, nil
	case dict.TypeIPv6Prefix:
		return attrs.Value{Type: t, Bytes: append([]byte(nil), data...)}, nil
	case dict.TypeEther, dict.TypeIfid, dict.TypeOctets:
		return attrs.Value{Type: t, Bytes: append([]byte(nil), data...)}, nil
	case dict.TypeString:
		return attrs.Value{Type: t, Str: string(data)}, nil
	}
	return attrs.Value{Type: dict.TypeOctets, Bytes: append([]byte(nil), data...)}, nil
}
