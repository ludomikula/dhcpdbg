package wire6

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ludomikula/dhcpdbg/internal/attrs"
	"github.com/ludomikula/dhcpdbg/internal/dict"
)

// loadV6 is shared with wire6_test.go via the package; not redeclared here.

// TestEncodeIANAWithIAAddr verifies the IA-NA option byte layout for a
// SOLICIT carrying one IA-Addr. Per RFC 8415 §21.4 & §21.6.
func TestEncodeIANAWithIAAddr(t *testing.T) {
	proto := loadV6(t)
	input := `Transaction-ID = 0xabcdef
Packet-Type = Solicit
IA-NA.IAID = 1
IA-NA.T1 = 3600
IA-NA.T2 = 5400
IA-NA.Options.IA-Addr.IPv6-Address = 2001:db8::1
IA-NA.Options.IA-Addr.Preferred-Lifetime = 3600
IA-NA.Options.IA-Addr.Valid-Lifetime = 7200
`
	records, err := attrs.ReadList(strings.NewReader(input), proto)
	if err != nil {
		t.Fatalf("ReadList: %v", err)
	}
	wire, err := Encode(records[0], proto)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// Hexdump for diagnostics.
	if testing.Verbose() {
		t.Logf("wire = %s", hex.EncodeToString(wire))
	}
	// Header: 01 ab cd ef (SOLICIT + 24-bit txn).
	if wire[0] != 0x01 || wire[1] != 0xab || wire[2] != 0xcd || wire[3] != 0xef {
		t.Fatalf("bad header: %02x%02x%02x%02x", wire[0], wire[1], wire[2], wire[3])
	}
	// Expected IA-NA body: 00 00 00 01 | 00 00 0e 10 | 00 00 15 18 | <IA-Addr opt>
	// Find the IA-NA option in the byte stream.
	expectedIANA, _ := hex.DecodeString("000300280000000100000e10000015180005001820010db800000000000000000000000100000e1000001c20")
	if !bytes.Contains(wire, expectedIANA) {
		t.Fatalf("IA-NA bytes not found.\nwant: %s\ngot:  %s", hex.EncodeToString(expectedIANA), hex.EncodeToString(wire))
	}
}

// TestEncodeClientIDLLT verifies DUID-LLT encoding (RFC 8415 §11.2).
func TestEncodeClientIDLLT(t *testing.T) {
	proto := loadV6(t)
	input := `Transaction-ID = 0xabcdef
Packet-Type = Solicit
Client-ID.DUID = LLT
Client-ID.LLT.Hardware-Type = 1
Client-ID.LLT.Time = 0
Client-ID.LLT.Ethernet.Address = 02:00:00:00:00:01
`
	records, err := attrs.ReadList(strings.NewReader(input), proto)
	if err != nil {
		t.Fatalf("ReadList: %v", err)
	}
	wire, err := Encode(records[0], proto)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// Expected: option code 0001, len 000e, then DUID body
	// 00 01 (DUID-LLT) | 00 01 (hwtype=Ethernet) | 00 00 00 00 (time) | 02 00 00 00 00 01 (MAC)
	expectedCID, _ := hex.DecodeString("0001000e0001000100000000020000000001")
	if !bytes.Contains(wire, expectedCID) {
		t.Fatalf("Client-ID bytes not found.\nwant: %s\ngot:  %s", hex.EncodeToString(expectedCID), hex.EncodeToString(wire))
	}
}

// TestStatusCodeRoundTrip verifies Status-Code = { Value, Message } encodes
// and decodes back through the structured codec.
func TestStatusCodeRoundTrip(t *testing.T) {
	proto := loadV6(t)
	input := `Transaction-ID = 0xabcdef
Packet-Type = Reply
Status-Code.Value = NoAddrsAvail
Status-Code.Message = "pool exhausted"
`
	records, err := attrs.ReadList(strings.NewReader(input), proto)
	if err != nil {
		t.Fatalf("ReadList: %v", err)
	}
	wire, err := Encode(records[0], proto)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// Decode the packet back.
	pkt, err := Decode(wire, proto)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	// Find Status-Code among decoded pairs.
	var sc *attrs.Pair
	for i := range pkt.Pairs {
		if pkt.Pairs[i].Attr != nil && pkt.Pairs[i].Attr.Name == "Status-Code" {
			sc = &pkt.Pairs[i]
			break
		}
	}
	if sc == nil {
		t.Fatal("Status-Code option not present in decoded packet")
	}
	if sc.Value.Type != dict.TypeStruct {
		t.Fatalf("Status-Code decoded as %s, want struct", sc.Value.Type)
	}
	var sawValue, sawMsg bool
	for _, mv := range sc.Value.Members {
		switch mv.Member.Name {
		case "Value":
			if mv.Value.Uint != 2 { // NoAddrsAvail
				t.Fatalf("Status-Code.Value = %d, want 2", mv.Value.Uint)
			}
			sawValue = true
		case "Message":
			if mv.Value.Str != "pool exhausted" {
				t.Fatalf("Status-Code.Message = %q", mv.Value.Str)
			}
			sawMsg = true
		}
	}
	if !sawValue || !sawMsg {
		t.Fatalf("missing decoded MEMBERs (value=%v, message=%v)", sawValue, sawMsg)
	}
}

// TestEncodeIAPD verifies IA-PD + IA-PD-Prefix nesting (RFC 8415 §21.21,
// §21.22).
func TestEncodeIAPD(t *testing.T) {
	proto := loadV6(t)
	input := `Transaction-ID = 0xabcdef
Packet-Type = Solicit
IA-PD.IAID = 7
IA-PD.T1 = 3600
IA-PD.T2 = 5400
IA-PD.Options.IA-PD-Prefix.Preferred-Lifetime = 3600
IA-PD.Options.IA-PD-Prefix.Valid-Lifetime = 7200
IA-PD.Options.IA-PD-Prefix.IPv6-Prefix = 2001:db8:1::/48
`
	records, err := attrs.ReadList(strings.NewReader(input), proto)
	if err != nil {
		t.Fatalf("ReadList: %v", err)
	}
	wire, err := Encode(records[0], proto)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// Expect IA-PD (option 25 = 0x0019). Find the IA-PD option header.
	wantHead, _ := hex.DecodeString("0019")
	if !bytes.Contains(wire, wantHead) {
		t.Fatalf("IA-PD (option 25) not found in wire bytes: %s", hex.EncodeToString(wire))
	}
	// Round-trip decode and confirm we can locate the nested IA-PD-Prefix.
	pkt, err := Decode(wire, proto)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	var iapd *attrs.Pair
	for i := range pkt.Pairs {
		if pkt.Pairs[i].Attr != nil && pkt.Pairs[i].Attr.Name == "IA-PD" {
			iapd = &pkt.Pairs[i]
			break
		}
	}
	if iapd == nil {
		t.Fatal("IA-PD not decoded")
	}
	// Find Options member and its nested IA-PD-Prefix.
	for _, mv := range iapd.Value.Members {
		if mv.Member.Name == "Options" {
			if len(mv.Value.Group) == 0 {
				t.Fatal("IA-PD.Options decoded with no sub-options")
			}
			sub := mv.Value.Group[0]
			if sub.Attr.Name != "IA-PD-Prefix" {
				t.Fatalf("nested option %s, want IA-PD-Prefix", sub.Attr.Name)
			}
			return
		}
	}
	t.Fatal("IA-PD.Options member missing")
}
