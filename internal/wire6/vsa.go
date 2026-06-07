package wire6

import (
	"encoding/binary"
	"fmt"

	"github.com/ludomikula/dhcpdbg/internal/attrs"
	"github.com/ludomikula/dhcpdbg/internal/dict"
)

// encodeVendorOpts serialises a Vendor-Opts (option 17) Value.
//
// Layout (RFC 8415 §21.17):
//
//	+------+------------------------------+
//	| PEN  | nested option list (TLV)     |
//	|  4B  | code(2) + len(2) + value...  |
//	+------+------------------------------+
//
// The PEN may be set via the synthetic `Vendor-Opts.PEN = N` MEMBER if a
// VSAValue is present, or supplied directly via Value.VSA.
func encodeVendorOpts(v attrs.Value) ([]byte, error) {
	if v.VSA == nil {
		// Fall back to the opaque-octets path for users passing a raw blob.
		return append([]byte(nil), v.Bytes...), nil
	}
	body, err := encodeGroupOptions(v.VSA.Options)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(out[0:4], v.VSA.PEN)
	copy(out[4:], body)
	return out, nil
}

// decodeVendorOpts unpacks the PEN + nested option list.
func decodeVendorOpts(data []byte, proto *dict.Protocol) (attrs.Value, error) {
	if len(data) < 4 {
		return attrs.Value{}, fmt.Errorf("Vendor-Opts: short option (%d bytes)", len(data))
	}
	pen := binary.BigEndian.Uint32(data[0:4])
	pairs, err := decodeOptions(data[4:], proto)
	if err != nil {
		return attrs.Value{}, err
	}
	return attrs.Value{
		Type: dict.TypeVSA,
		VSA: &attrs.VSAValue{
			PEN:     pen,
			Options: pairs,
		},
	}, nil
}
