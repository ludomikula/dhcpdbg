package wire4

import (
	"github.com/ludomikula/dhcpdbg/internal/dict"
)

// SynthesizeStructured attaches synthetic MEMBER lists to DHCPv4 options
// whose dictionary type doesn't carry one but whose on-wire layout is a
// fixed struct. Call this on a *dict.Protocol returned by LoadDHCPv4 before
// using the structured codecs.
//
// V-I-Vendor-Class (124, RFC 3925 §3): the FR dictionary types it as plain
// `octets`, but every option-124 segment is `PEN(4) + len(1) + class-data`.
// Attaching synthetic `PEN` + `Data` members lets the dotted-path walker
// accept `V-I-Vendor-Class[N].PEN = ...` and `V-I-Vendor-Class[N].Data = ...`.
//
// V-I-Vendor-Specific (125, RFC 3925 §4): the FR dictionary types this as
// `vsa`, which the dotted walker doesn't know how to descend into. We add
// `PEN` + `Options(group)` members so `.PEN` and `.Options.<sub>` resolve.
//
// Relay-Agent-Information (82) is already `tlv` and its sub-attrs are now
// in its Children map, so it works without any synthetic adjustment.
func SynthesizeStructured(proto *dict.Protocol) {
	if a, ok := proto.AttrByName("V-I-Vendor-Class"); ok && len(a.Members) == 0 {
		a.Type = dict.TypeStruct
		a.Members = []*dict.Member{
			{Name: "PEN", Type: dict.TypeUint32},
			{Name: "Data", Type: dict.TypeOctets},
		}
	}
	if a, ok := proto.AttrByName("V-I-Vendor-Specific"); ok && len(a.Members) == 0 {
		a.Type = dict.TypeStruct
		a.Members = []*dict.Member{
			{Name: "PEN", Type: dict.TypeUint32},
			{Name: "Options", Type: dict.TypeGroup},
		}
	}
}
