package wire4

import (
	"encoding/binary"
	"fmt"

	"github.com/ludomikula/dhcpdbg/internal/attrs"
	"github.com/ludomikula/dhcpdbg/internal/dict"
)

// encodeVIVendorSpecific serialises one V-I-Vendor-Specific option-125
// segment per RFC 3925 §4:
//
//	+-------------+-----+----------------+
//	|   PEN (4)   |  L  |  TLVs (L)      |
//	+-------------+-----+----------------+
//	  enterprise   1-B   code(1)+len(1)+value, repeated
//
// Input shape (post SynthesizeStructured): the V-I-Vendor-Specific
// attribute is a struct with PEN (uint32) + Options (group). The Options
// group carries the vendor sub-options as nested Pairs whose attribute is
// from the vendor block.
func encodeVIVendorSpecific(v attrs.Value) ([]byte, error) {
	pen, options := pickPENAndOptions(v)
	body, err := encodeTLV11List(options)
	if err != nil {
		return nil, err
	}
	if len(body) > 0xff {
		return nil, fmt.Errorf("V-I-Vendor-Specific PEN=%d: payload %d bytes exceeds 255 (RFC 3925)", pen, len(body))
	}
	out := make([]byte, 5+len(body))
	binary.BigEndian.PutUint32(out[0:4], pen)
	out[4] = byte(len(body))
	copy(out[5:], body)
	return out, nil
}

// decodeVIVendorSpecific parses one option-125 payload. Multiple PEN
// segments inside one option body are handled too — each becomes its own
// Pair on the way out.
func decodeVIVendorSpecific(data []byte, proto *dict.Protocol) ([]attrs.Pair, error) {
	out := make([]attrs.Pair, 0, 2)
	root, _ := proto.AttrByName("V-I-Vendor-Specific")
	for i := 0; i < len(data); {
		if i+5 > len(data) {
			return nil, fmt.Errorf("V-I-Vendor-Specific: short PEN segment at offset %d", i)
		}
		pen := binary.BigEndian.Uint32(data[i : i+4])
		l := int(data[i+4])
		if i+5+l > len(data) {
			return nil, fmt.Errorf("V-I-Vendor-Specific PEN=%d: payload %d > remaining %d", pen, l, len(data)-i-5)
		}
		body := data[i+5 : i+5+l]
		// Resolve sub-options by enterprise-number from the protocol's
		// per-vendor table populated by BEGIN-VENDOR/END-VENDOR blocks.
		var vendorChildren map[uint32]*dict.Attr
		if vendorMap, ok := proto.ByVendor[pen]; ok {
			vendorChildren = vendorMap
		}
		subOpts, err := decodeTLV11List(body, vendorChildren)
		if err != nil {
			return nil, err
		}
		segValue := attrs.Value{Type: dict.TypeStruct}
		segValue.Members = append(segValue.Members, attrs.MemberValue{
			Member: &dict.Member{Name: "PEN", Type: dict.TypeUint32},
			Value:  attrs.Value{Type: dict.TypeUint32, Uint: uint64(pen)},
		})
		segValue.Members = append(segValue.Members, attrs.MemberValue{
			Member: &dict.Member{Name: "Options", Type: dict.TypeGroup},
			Value:  attrs.Value{Type: dict.TypeGroup, Group: subOpts},
		})
		out = append(out, attrs.Pair{Attr: root, Value: segValue})
		i += 5 + l
	}
	return out, nil
}

// encodeVIVendorClass serialises one V-I-Vendor-Class option-124 segment
// per RFC 3925 §3:
//
//	+-------------+-----+-------------+
//	|   PEN (4)   |  L  |  class-data |
//	+-------------+-----+-------------+
func encodeVIVendorClass(v attrs.Value) ([]byte, error) {
	pen, data := pickPENAndData(v)
	if len(data) > 0xff {
		return nil, fmt.Errorf("V-I-Vendor-Class PEN=%d: class-data %d bytes exceeds 255 (RFC 3925)", pen, len(data))
	}
	out := make([]byte, 5+len(data))
	binary.BigEndian.PutUint32(out[0:4], pen)
	out[4] = byte(len(data))
	copy(out[5:], data)
	return out, nil
}

// decodeVIVendorClass parses option-124 payload, returning one Pair per PEN
// segment. The Value carries `PEN` + `Data` members so output round-trips
// through the dotted-path writer.
func decodeVIVendorClass(data []byte, proto *dict.Protocol) ([]attrs.Pair, error) {
	out := make([]attrs.Pair, 0, 2)
	root, _ := proto.AttrByName("V-I-Vendor-Class")
	for i := 0; i < len(data); {
		if i+5 > len(data) {
			return nil, fmt.Errorf("V-I-Vendor-Class: short PEN segment at offset %d", i)
		}
		pen := binary.BigEndian.Uint32(data[i : i+4])
		l := int(data[i+4])
		if i+5+l > len(data) {
			return nil, fmt.Errorf("V-I-Vendor-Class PEN=%d: class-data %d > remaining %d", pen, l, len(data)-i-5)
		}
		body := append([]byte(nil), data[i+5:i+5+l]...)
		segValue := attrs.Value{Type: dict.TypeStruct}
		segValue.Members = append(segValue.Members, attrs.MemberValue{
			Member: &dict.Member{Name: "PEN", Type: dict.TypeUint32},
			Value:  attrs.Value{Type: dict.TypeUint32, Uint: uint64(pen)},
		})
		segValue.Members = append(segValue.Members, attrs.MemberValue{
			Member: &dict.Member{Name: "Data", Type: dict.TypeOctets},
			Value:  attrs.Value{Type: dict.TypeOctets, Bytes: body},
		})
		out = append(out, attrs.Pair{Attr: root, Value: segValue})
		i += 5 + l
	}
	return out, nil
}

// pickPENAndOptions extracts (PEN, Options-list) from a struct Value where
// the user populated the synthetic PEN + Options members.
func pickPENAndOptions(v attrs.Value) (uint32, []attrs.Pair) {
	var pen uint32
	var opts []attrs.Pair
	for _, mv := range v.Members {
		switch mv.Member.Name {
		case "PEN":
			pen = uint32(mv.Value.Uint)
		case "Options":
			opts = mv.Value.Group
		}
	}
	return pen, opts
}

// pickPENAndData extracts (PEN, Data-bytes) from a struct Value where the
// user populated the synthetic PEN + Data members.
func pickPENAndData(v attrs.Value) (uint32, []byte) {
	var pen uint32
	var data []byte
	for _, mv := range v.Members {
		switch mv.Member.Name {
		case "PEN":
			pen = uint32(mv.Value.Uint)
		case "Data":
			if mv.Value.Type == dict.TypeString {
				data = []byte(mv.Value.Str)
			} else {
				data = append([]byte(nil), mv.Value.Bytes...)
			}
		}
	}
	return pen, data
}
