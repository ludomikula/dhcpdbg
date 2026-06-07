package wire4

import (
	"strings"
	"testing"

	"github.com/ludomikula/dhcpdbg/internal/attrs"
	"github.com/ludomikula/dhcpdbg/internal/dict"
)

const discoverInput = `Client-Hardware-Address = 02:00:00:00:00:01
Hostname = "lab-discover"
Parameter-Request-List = Subnet-Mask
Parameter-Request-List = Router-Address
Parameter-Request-List = Domain-Name-Server
Message-Type = Discover
Transaction-Id = 0x12345678
`

func loadV4(t *testing.T) *dict.Protocol {
	t.Helper()
	proto, err := dict.LoadDHCPv4()
	if err != nil {
		t.Fatalf("load dhcpv4: %v", err)
	}
	return proto
}

func TestEncodeDiscoverHasMagicCookie(t *testing.T) {
	proto := loadV4(t)
	pairs, err := attrs.ReadList(strings.NewReader(discoverInput), proto)
	if err != nil {
		t.Fatalf("ReadList: %v", err)
	}
	buf, err := Encode(pairs[0], proto)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if len(buf) < 240 {
		t.Fatalf("encoded packet too short: %d", len(buf))
	}
	if buf[236] != 0x63 || buf[237] != 0x82 || buf[238] != 0x53 || buf[239] != 0x63 {
		t.Fatalf("bad magic cookie: %x %x %x %x", buf[236], buf[237], buf[238], buf[239])
	}
	if buf[0] != 1 {
		t.Fatalf("expected op=1 (BOOTREQUEST), got %d", buf[0])
	}
}

func TestRoundTripDiscover(t *testing.T) {
	proto := loadV4(t)
	pairs, err := attrs.ReadList(strings.NewReader(discoverInput), proto)
	if err != nil {
		t.Fatalf("ReadList: %v", err)
	}
	wire, err := Encode(pairs[0], proto)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	pkt, err := Decode(wire, proto, "")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if pkt.MessageType != 1 {
		t.Fatalf("expected DISCOVER (1), got %d", pkt.MessageType)
	}
	if pkt.XID != 0x12345678 {
		t.Fatalf("expected xid 0x12345678, got %#x", pkt.XID)
	}
	// Should round-trip the Hostname.
	var foundHost bool
	for _, p := range pkt.Pairs {
		if p.Attr.Name == "Hostname" {
			if p.Value.Str != "lab-discover" {
				t.Fatalf("Hostname round-trip: %q", p.Value.Str)
			}
			foundHost = true
		}
	}
	if !foundHost {
		t.Fatalf("Hostname not present in decoded packet")
	}
}

func TestPRLAggregation(t *testing.T) {
	// Three Parameter-Request-List entries should land in a single option
	// payload of length 3 (RFC 2132 §9.8).
	proto := loadV4(t)
	pairs, err := attrs.ReadList(strings.NewReader(discoverInput), proto)
	if err != nil {
		t.Fatalf("ReadList: %v", err)
	}
	wire, err := Encode(pairs[0], proto)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// Scan options for code 55.
	i := 240
	found := false
	for i < len(wire) {
		c := wire[i]
		if c == 0 {
			i++
			continue
		}
		if c == 0xff {
			break
		}
		l := int(wire[i+1])
		if c == 55 {
			if l != 3 {
				t.Fatalf("PRL length %d, want 3", l)
			}
			payload := wire[i+2 : i+2+l]
			if payload[0] != 1 || payload[1] != 3 || payload[2] != 6 {
				t.Fatalf("PRL payload %v", payload)
			}
			found = true
			break
		}
		i += 2 + l
	}
	if !found {
		t.Fatal("PRL (option 55) not found in encoded packet")
	}
}
