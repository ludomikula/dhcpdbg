package wire4

import (
	"fmt"

	"github.com/ludomikula/dhcpdbg/internal/attrs"
	"github.com/ludomikula/dhcpdbg/internal/dict"
)

// encodeTLV11 writes a single DHCPv4-style 1-byte-code / 1-byte-length
// sub-option. Used by option 82 (Relay-Agent-Info) and the inner TLV layer
// of option 125's per-PEN segments.
func encodeTLV11(code uint8, data []byte) ([]byte, error) {
	if len(data) > 0xff {
		return nil, fmt.Errorf("sub-option %d: value too long for 1-byte length (%d bytes)", code, len(data))
	}
	out := make([]byte, 2+len(data))
	out[0] = code
	out[1] = byte(len(data))
	copy(out[2:], data)
	return out, nil
}

// encodeTLV11List walks a sequence of Pairs (typically a group's children)
// and emits them as concatenated 1/1 sub-TLVs. Each pair's value is
// serialised via the standard scalar/struct encoder used elsewhere in
// wire4; container types fall through as opaque octets if no codec is
// registered for them at this layer.
func encodeTLV11List(pairs []attrs.Pair) ([]byte, error) {
	out := make([]byte, 0, 64)
	for _, p := range pairs {
		if p.Attr == nil {
			continue
		}
		val, err := encodeChildValue(p)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", p.Attr.Name, err)
		}
		tlv, err := encodeTLV11(uint8(p.Attr.Code), val)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", p.Attr.Name, err)
		}
		out = append(out, tlv...)
	}
	return out, nil
}

// encodeChildValue serialises one DHCPv4 sub-option value, dispatching to
// the same primitive encoder the top-level option codec uses.
func encodeChildValue(p attrs.Pair) ([]byte, error) {
	return encodeValue(p.Attr, p.Value)
}

// decodeTLV11List parses a stream of 1/1 sub-TLVs back into a list of
// Pairs. children is the parent's Children map (sub-code → sub-attribute).
// Unknown sub-codes become a synthetic `Sub-<code>` attr with octets value.
func decodeTLV11List(data []byte, children map[uint32]*dict.Attr) ([]attrs.Pair, error) {
	var out []attrs.Pair
	for i := 0; i < len(data); {
		if i+2 > len(data) {
			return nil, fmt.Errorf("tlv11: truncated header at offset %d", i)
		}
		code := data[i]
		l := int(data[i+1])
		if i+2+l > len(data) {
			return nil, fmt.Errorf("tlv11: sub-option %d truncated (need %d, have %d)", code, l, len(data)-i-2)
		}
		payload := data[i+2 : i+2+l]
		child, ok := children[uint32(code)]
		if !ok {
			child = &dict.Attr{
				Name: fmt.Sprintf("Sub-%d", code),
				Code: uint32(code),
				Type: dict.TypeOctets,
			}
		}
		v, err := decodeOneTLV11(child, payload)
		if err != nil {
			return nil, err
		}
		out = append(out, attrs.Pair{Attr: child, Value: v})
		i += 2 + l
	}
	return out, nil
}

// decodeOneTLV11 decodes a single sub-option payload against the child
// attribute's declared type, falling back to opaque octets for types this
// shallow decoder doesn't know about.
func decodeOneTLV11(child *dict.Attr, data []byte) (attrs.Value, error) {
	pairs, err := decodeOption(child, data)
	if err != nil {
		return attrs.Value{Type: dict.TypeOctets, Bytes: append([]byte(nil), data...)}, nil
	}
	if len(pairs) == 1 {
		return pairs[0].Value, nil
	}
	// Array-decoded result — surface the raw bytes; printed output will be
	// hex, which the user can interpret.
	return attrs.Value{Type: dict.TypeOctets, Bytes: append([]byte(nil), data...)}, nil
}
