package wire4

import (
	"fmt"

	"github.com/ludomikula/dhcpdbg/internal/attrs"
	"github.com/ludomikula/dhcpdbg/internal/dict"
)

// option43Code is the DHCPv4 Vendor-Specific-Information option number.
const option43Code = 43

// encodeDecodedOption43 serialises a Decoded-Option-43 Value into the bytes
// that will become the option-43 payload on the wire. The value must contain
// exactly one vendor block (Decoded-Option-43.<Vendor>); the block's group
// children become 1-byte-code / 1-byte-length sub-TLVs. The 276 → 43 code
// rewrite happens at the caller (encodeOptions in options.go).
func encodeDecodedOption43(v attrs.Value) ([]byte, error) {
	if len(v.Group) == 0 {
		return nil, fmt.Errorf("Decoded-Option-43: empty (set Decoded-Option-43.<Vendor>.<Field> ...)")
	}
	if len(v.Group) > 1 {
		// Option 43 has no PEN; it carries exactly one vendor's bytes.
		// Mixing vendor namespaces in a single record is almost certainly
		// a mistake, so refuse rather than silently concatenating.
		names := make([]string, 0, len(v.Group))
		for _, g := range v.Group {
			names = append(names, g.Attr.Name)
		}
		return nil, fmt.Errorf("Decoded-Option-43: exactly one vendor block expected, got %d (%v)", len(v.Group), names)
	}
	vendor := v.Group[0]
	if len(vendor.Value.Group) == 0 {
		return nil, fmt.Errorf("Decoded-Option-43.%s: no sub-options set", vendor.Attr.Name)
	}
	return encodeTLV11List(vendor.Value.Group)
}

// decodeOption43 walks an option-43 payload as 1/1 sub-TLVs against the
// named vendor block under Decoded-Option-43. Returns a Pair carrying a
// Decoded-Option-43 attribute whose Group has a single vendor entry, which
// itself holds the decoded sub-options. The dotted-form printer renders
// this back as Decoded-Option-43.<Vendor>.<Field> = <value>.
//
// Returns (nil, error) when proto is missing Decoded-Option-43 or the named
// vendor block — caller should fall through to opaque-octets emission.
func decodeOption43(proto *dict.Protocol, vendorName string, data []byte) (*attrs.Pair, error) {
	decoded, ok := proto.AttrByName("Decoded-Option-43")
	if !ok {
		return nil, fmt.Errorf("Decoded-Option-43 not in dictionary")
	}
	vendor, ok := lookupChildByName(decoded, vendorName)
	if !ok {
		return nil, fmt.Errorf("Decoded-Option-43.%s not in dictionary", vendorName)
	}
	subs, err := decodeTLV11List(data, vendor.Children)
	if err != nil {
		return nil, err
	}
	// Build the nested value:
	//   Decoded-Option-43 (tlv) = Group{
	//     <vendor> (tlv) = Group{ <leaves...> }
	//   }
	vendorValue := attrs.Value{Type: dict.TypeTLV, Group: subs}
	wrapped := attrs.Value{
		Type:  dict.TypeTLV,
		Group: []attrs.Pair{{Attr: vendor, Value: vendorValue}},
	}
	return &attrs.Pair{Attr: decoded, Value: wrapped}, nil
}

// lookupChildByName scans a parent attr's Children map for a sub-attribute
// matching name. Children is keyed by sub-code so we have to iterate; for
// the small per-parent maps that's fine.
func lookupChildByName(parent *dict.Attr, name string) (*dict.Attr, bool) {
	for _, c := range parent.Children {
		if c.Name == name {
			return c, true
		}
	}
	return nil, false
}
