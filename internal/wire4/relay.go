package wire4

import (
	"fmt"

	"github.com/ludomikula/dhcpdbg/internal/attrs"
	"github.com/ludomikula/dhcpdbg/internal/dict"
)

// encodeRelayAgentInfo serialises a Relay-Agent-Information (option 82)
// option's payload — a sequence of 1-byte-code / 1-byte-length sub-TLVs.
//
// Input shape: the user's Value carries v.Group with one Pair per
// sub-option (Circuit-Id, Remote-Id, Relay-Link-Selection, ...). Each
// sub-option's wire form is `code(1) + len(1) + value`.
func encodeRelayAgentInfo(v attrs.Value) ([]byte, error) {
	return encodeTLV11List(v.Group)
}

// decodeRelayAgentInfo parses a Relay-Agent-Information payload into a
// Value carrying the sub-options as a Group, keyed by sub-attribute from
// dictionary.rfc3046 (Circuit-Id, Remote-Id, Relay-Link-Selection, ...).
func decodeRelayAgentInfo(parent *dict.Attr, data []byte, _ *dict.Protocol) (attrs.Value, error) {
	if parent == nil || parent.Children == nil {
		return attrs.Value{Type: dict.TypeOctets, Bytes: append([]byte(nil), data...)},
			fmt.Errorf("Relay-Agent-Information: no Children registered (dictionary.rfc3046 missing?)")
	}
	subOpts, err := decodeTLV11List(data, parent.Children)
	if err != nil {
		return attrs.Value{}, err
	}
	return attrs.Value{Type: dict.TypeTLV, Group: subOpts}, nil
}
