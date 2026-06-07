package wire6

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/ludomikula/dhcpdbg/internal/attrs"
	"github.com/ludomikula/dhcpdbg/internal/dict"
)

const solicitInput = `Packet-Type = Solicit
Transaction-ID = 0xabcdef
Client-ID = 0x00030001020000000001
Option-Request = DNS-Servers
Option-Request = Domain-List
`

func loadV6(t *testing.T) *dict.Protocol {
	t.Helper()
	proto, err := dict.LoadDHCPv6()
	if err != nil {
		t.Fatalf("load dhcpv6: %v", err)
	}
	return proto
}

func TestEncodeSolicitHeader(t *testing.T) {
	proto := loadV6(t)
	pairs, err := attrs.ReadList(strings.NewReader(solicitInput), proto)
	if err != nil {
		t.Fatalf("ReadList: %v", err)
	}
	wire, err := Encode(pairs[0], proto)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if wire[0] != 1 {
		t.Fatalf("msg-type want 1 (SOLICIT), got %d", wire[0])
	}
	if wire[1] != 0xab || wire[2] != 0xcd || wire[3] != 0xef {
		t.Fatalf("transaction id want abcdef, got %02x%02x%02x", wire[1], wire[2], wire[3])
	}
}

func TestOROAggregation(t *testing.T) {
	// Two Option-Request entries must become a single ORO option of length 4
	// (two 2-byte codes).
	proto := loadV6(t)
	pairs, err := attrs.ReadList(strings.NewReader(solicitInput), proto)
	if err != nil {
		t.Fatalf("ReadList: %v", err)
	}
	wire, err := Encode(pairs[0], proto)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	i := 4
	var got bool
	for i+4 <= len(wire) {
		code := binary.BigEndian.Uint16(wire[i : i+2])
		l := int(binary.BigEndian.Uint16(wire[i+2 : i+4]))
		if code == 6 { // Option-Request
			if l != 4 {
				t.Fatalf("ORO length %d, want 4", l)
			}
			p := wire[i+4 : i+4+l]
			if binary.BigEndian.Uint16(p[0:2]) != 23 || binary.BigEndian.Uint16(p[2:4]) != 24 {
				t.Fatalf("ORO payload %v", p)
			}
			got = true
			break
		}
		i += 4 + l
	}
	if !got {
		t.Fatal("Option-Request (code 6) not found")
	}
}

func TestRoundTripSolicit(t *testing.T) {
	proto := loadV6(t)
	pairs, err := attrs.ReadList(strings.NewReader(solicitInput), proto)
	if err != nil {
		t.Fatalf("ReadList: %v", err)
	}
	wire, err := Encode(pairs[0], proto)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	pkt, err := Decode(wire, proto)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if pkt.MessageType != 1 {
		t.Fatalf("MessageType: want 1, got %d", pkt.MessageType)
	}
	if pkt.TxnID != 0xabcdef {
		t.Fatalf("TxnID: want 0xabcdef, got %#x", pkt.TxnID)
	}
}
