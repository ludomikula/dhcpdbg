package wire4

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ludomikula/dhcpdbg/internal/attrs"
	"github.com/ludomikula/dhcpdbg/internal/dict"
)

func loadV4Structured(t *testing.T) *dict.Protocol {
	t.Helper()
	proto, err := dict.LoadDHCPv4()
	if err != nil {
		t.Fatalf("load dhcpv4: %v", err)
	}
	SynthesizeStructured(proto)
	return proto
}

// TestRelayAgentEncode checks the option 82 layout per RFC 3046 §2: a
// concatenated sequence of 1-byte-code / 1-byte-length sub-TLVs.
func TestRelayAgentEncode(t *testing.T) {
	proto := loadV4Structured(t)
	input := `Client-Hardware-Address = 02:00:00:00:00:01
Transaction-Id = 0xcafebabe
Message-Type = Discover
Relay-Agent-Information.Circuit-Id = "port=A/2"
Relay-Agent-Information.Remote-Id  = "modem=001abc002233"
`
	records, err := attrs.ReadList(strings.NewReader(input), proto)
	if err != nil {
		t.Fatalf("ReadList: %v", err)
	}
	wire, err := Encode(records[0], proto)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// option 82 (0x52) followed by len 30, then sub 1 (Circuit-Id) and sub 2 (Remote-Id)
	want, _ := hex.DecodeString("521e01087" + "06f72743d412f32" + "021" + "26d6f64656d3d303031616263303032323333")
	if !bytes.Contains(wire, want) {
		t.Fatalf("Relay-Agent option not found.\nwant: %s\ngot:  %s",
			hex.EncodeToString(want), hex.EncodeToString(wire))
	}
}

// TestRelayAgentRoundTrip encodes then decodes a Relay-Agent option and
// confirms both sub-options come back through the structured decoder.
func TestRelayAgentRoundTrip(t *testing.T) {
	proto := loadV4Structured(t)
	input := `Client-Hardware-Address = 02:00:00:00:00:01
Transaction-Id = 0x11223344
Message-Type = Discover
Relay-Agent-Information.Circuit-Id = "port=A/2"
Relay-Agent-Information.Remote-Id  = "modem=001abc002233"
`
	records, err := attrs.ReadList(strings.NewReader(input), proto)
	if err != nil {
		t.Fatalf("ReadList: %v", err)
	}
	wire, err := Encode(records[0], proto)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	pkt, err := Decode(wire, proto, "")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	var relay *attrs.Pair
	for i := range pkt.Pairs {
		if pkt.Pairs[i].Attr != nil && pkt.Pairs[i].Attr.Name == "Relay-Agent-Information" {
			relay = &pkt.Pairs[i]
			break
		}
	}
	if relay == nil {
		t.Fatal("Relay-Agent-Information not decoded")
	}
	var sawCircuit, sawRemote bool
	for _, sub := range relay.Value.Group {
		switch sub.Attr.Name {
		case "Circuit-Id":
			if string(sub.Value.Bytes) != "port=A/2" {
				t.Fatalf("Circuit-Id = %q", sub.Value.Bytes)
			}
			sawCircuit = true
		case "Remote-Id":
			if string(sub.Value.Bytes) != "modem=001abc002233" {
				t.Fatalf("Remote-Id = %q", sub.Value.Bytes)
			}
			sawRemote = true
		}
	}
	if !sawCircuit || !sawRemote {
		t.Fatalf("missing sub-options (circuit=%v, remote=%v)", sawCircuit, sawRemote)
	}
}

// TestVIVendorClassEncode checks option 124 layout per RFC 3925 §3.
func TestVIVendorClassEncode(t *testing.T) {
	proto := loadV4Structured(t)
	input := `Client-Hardware-Address = 02:00:00:00:00:01
Transaction-Id = 0x11223344
Message-Type = Discover
V-I-Vendor-Class.PEN  = 3561
V-I-Vendor-Class.Data = "Broadband-CPE"
`
	records, err := attrs.ReadList(strings.NewReader(input), proto)
	if err != nil {
		t.Fatalf("ReadList: %v", err)
	}
	wire, err := Encode(records[0], proto)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// option 124 (0x7c) len 0x12, then PEN 3561 (0x00000de9), data-len 13,
	// then "Broadband-CPE".
	want, _ := hex.DecodeString("7c1200000de90d42726f616462616e642d435045")
	if !bytes.Contains(wire, want) {
		t.Fatalf("V-I-Vendor-Class option not found.\nwant: %s\ngot:  %s",
			hex.EncodeToString(want), hex.EncodeToString(wire))
	}
}

// TestVIVendorClassMultiPEN checks two PEN segments emit one after the
// other under the same option header.
func TestVIVendorClassMultiPEN(t *testing.T) {
	proto := loadV4Structured(t)
	input := `Client-Hardware-Address = 02:00:00:00:00:01
Transaction-Id = 0x11223344
Message-Type = Discover
V-I-Vendor-Class[0].PEN  = 3561
V-I-Vendor-Class[0].Data = "BBF"
V-I-Vendor-Class[1].PEN  = 4491
V-I-Vendor-Class[1].Data = "CableLabs"
`
	records, err := attrs.ReadList(strings.NewReader(input), proto)
	if err != nil {
		t.Fatalf("ReadList: %v", err)
	}
	wire, err := Encode(records[0], proto)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// Expect option 0x7c followed by both segments concatenated.
	// PEN 3561 = 0x00000de9, len 3 "BBF" -> 00 00 0d e9 03 42 42 46
	// PEN 4491 = 0x0000118b, len 9 "CableLabs" -> 00 00 11 8b 09 43 61 62 6c 65 4c 61 62 73
	want, _ := hex.DecodeString("7c" + "16" +
		"00000de9" + "03" + "424246" +
		"0000118b" + "09" + "4361626c654c616273")
	if !bytes.Contains(wire, want) {
		t.Fatalf("V-I-Vendor-Class multi-PEN not found.\nwant: %s\ngot:  %s",
			hex.EncodeToString(want), hex.EncodeToString(wire))
	}
}

// TestVIVendorSpecificEncode checks option 125 layout per RFC 3925 §4 with
// one PEN and one sub-TLV.
func TestVIVendorSpecificEncode(t *testing.T) {
	proto := loadV4Structured(t)
	input := `Client-Hardware-Address = 02:00:00:00:00:01
Transaction-Id = 0x11223344
Message-Type = Discover
V-I-Vendor-Specific.PEN                = 3561
V-I-Vendor-Specific.Options.ACS-URL    = "https://acs.example/cpe"
`
	records, err := attrs.ReadList(strings.NewReader(input), proto)
	if err != nil {
		t.Fatalf("ReadList: %v", err)
	}
	wire, err := Encode(records[0], proto)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// option 125 (0x7d) len 0x1e, PEN 3561, len 0x19,
	// sub-code 11 (ACS-URL), len 0x17, "https://acs.example/cpe".
	want, _ := hex.DecodeString("7d1e00000de9190b1768747470733a2f2f6163732e6578616d706c652f637065")
	if !bytes.Contains(wire, want) {
		t.Fatalf("V-I-Vendor-Specific option not found.\nwant: %s\ngot:  %s",
			hex.EncodeToString(want), hex.EncodeToString(wire))
	}
}

// TestVIVendorSpecificRoundTrip encodes and decodes a V-I-VSIO option,
// confirming the PEN and the named sub-option survive the round-trip.
func TestVIVendorSpecificRoundTrip(t *testing.T) {
	proto := loadV4Structured(t)
	input := `Client-Hardware-Address = 02:00:00:00:00:01
Transaction-Id = 0x11223344
Message-Type = Discover
V-I-Vendor-Specific.PEN                       = 3561
V-I-Vendor-Specific.Options.ACS-URL           = "https://acs.example/cpe"
V-I-Vendor-Specific.Options.Provisioning-Code = "ZONE-A"
`
	records, err := attrs.ReadList(strings.NewReader(input), proto)
	if err != nil {
		t.Fatalf("ReadList: %v", err)
	}
	wire, err := Encode(records[0], proto)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	pkt, err := Decode(wire, proto, "")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	var vsio *attrs.Pair
	for i := range pkt.Pairs {
		if pkt.Pairs[i].Attr != nil && pkt.Pairs[i].Attr.Name == "V-I-Vendor-Specific" {
			vsio = &pkt.Pairs[i]
			break
		}
	}
	if vsio == nil {
		t.Fatal("V-I-Vendor-Specific not decoded")
	}
	if vsio.Value.Type != dict.TypeStruct {
		t.Fatalf("decoded VSIO type %s, want struct", vsio.Value.Type)
	}
	var pen uint64
	var sawACS, sawProv bool
	for _, mv := range vsio.Value.Members {
		switch mv.Member.Name {
		case "PEN":
			pen = mv.Value.Uint
		case "Options":
			for _, sub := range mv.Value.Group {
				switch sub.Attr.Name {
				case "ACS-URL":
					if sub.Value.Type == dict.TypeOctets {
						if string(sub.Value.Bytes) != "https://acs.example/cpe" {
							t.Fatalf("ACS-URL bytes = %q", sub.Value.Bytes)
						}
					} else if sub.Value.Str != "https://acs.example/cpe" {
						t.Fatalf("ACS-URL = %q", sub.Value.Str)
					}
					sawACS = true
				case "Provisioning-Code":
					if sub.Value.Type == dict.TypeOctets {
						if string(sub.Value.Bytes) != "ZONE-A" {
							t.Fatalf("Provisioning-Code bytes = %q", sub.Value.Bytes)
						}
					} else if sub.Value.Str != "ZONE-A" {
						t.Fatalf("Provisioning-Code = %q", sub.Value.Str)
					}
					sawProv = true
				}
			}
		}
	}
	if pen != 3561 {
		t.Fatalf("PEN = %d, want 3561", pen)
	}
	if !sawACS || !sawProv {
		t.Fatalf("missing sub-options (ACS-URL=%v, Provisioning-Code=%v)", sawACS, sawProv)
	}
}
