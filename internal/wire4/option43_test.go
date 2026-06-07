package wire4

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ludomikula/dhcpdbg/internal/attrs"
	"github.com/ludomikula/dhcpdbg/internal/dict"
)

// loadV4Custom loads DHCPv4 with one or more extra dictionary files layered on
// top of the embedded set. Used by the option-43 tests to introduce custom
// vendor namespaces under Decoded-Option-43.
func loadV4Custom(t *testing.T, files map[string]string) *dict.Protocol {
	t.Helper()
	dir := t.TempDir()
	paths := make([]string, 0, len(files))
	for name, body := range files {
		full := filepath.Join(dir, name)
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatalf("WriteFile %s: %v", full, err)
		}
		paths = append(paths, full)
	}
	proto, err := dict.LoadDHCPv4(dict.WithCustomDicts(paths...))
	if err != nil {
		t.Fatalf("LoadDHCPv4 custom: %v", err)
	}
	SynthesizeStructured(proto)
	return proto
}

// TestDecodedOption43EncodeBroadbandForum verifies that the FreeRADIUS-shipped
// Broadband-Forum vendor under Decoded-Option-43 produces the expected wire
// bytes: option 43, then a single 1/1 sub-TLV (sub-code 1 = ACS-URL).
func TestDecodedOption43EncodeBroadbandForum(t *testing.T) {
	proto := loadV4(t)
	input := `Client-Hardware-Address = 02:00:00:00:00:01
Transaction-Id = 0x11223344
Message-Type = Discover
Decoded-Option-43.Broadband-Forum.ACS-URL = "https://acs.example/cpe"
`
	records, err := attrs.ReadList(strings.NewReader(input), proto)
	if err != nil {
		t.Fatalf("ReadList: %v", err)
	}
	wire, err := Encode(records[0], proto)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// option 43 (0x2b), payload-length 25 (0x19),
	// sub-code 1 (ACS-URL), sub-len 23 (0x17), then "https://acs.example/cpe".
	want, _ := hex.DecodeString("2b1901" + "17" + "68747470733a2f2f6163732e6578616d706c652f637065")
	if !bytes.Contains(wire, want) {
		t.Fatalf("option 43 (Broadband-Forum) not found.\nwant: %s\ngot:  %s",
			hex.EncodeToString(want), hex.EncodeToString(wire))
	}
}

// TestDecodedOption43RoundTripBroadbandForum encodes a Broadband-Forum payload
// and decodes it with the vendor hint, confirming the sub-options reappear
// under Decoded-Option-43.Broadband-Forum.
func TestDecodedOption43RoundTripBroadbandForum(t *testing.T) {
	proto := loadV4(t)
	input := `Client-Hardware-Address = 02:00:00:00:00:01
Transaction-Id = 0x11223344
Message-Type = Discover
Decoded-Option-43.Broadband-Forum.ACS-URL           = "https://acs.example/cpe"
Decoded-Option-43.Broadband-Forum.Provisioning-Code = "ZONE-A"
`
	records, err := attrs.ReadList(strings.NewReader(input), proto)
	if err != nil {
		t.Fatalf("ReadList: %v", err)
	}
	wire, err := Encode(records[0], proto)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	pkt, err := Decode(wire, proto, "Broadband-Forum")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	var decoded *attrs.Pair
	for i := range pkt.Pairs {
		if pkt.Pairs[i].Attr != nil && pkt.Pairs[i].Attr.Name == "Decoded-Option-43" {
			decoded = &pkt.Pairs[i]
			break
		}
	}
	if decoded == nil {
		t.Fatal("Decoded-Option-43 not present in decoded packet")
	}
	if len(decoded.Value.Group) != 1 {
		t.Fatalf("Decoded-Option-43.Group len = %d, want 1 vendor block", len(decoded.Value.Group))
	}
	vendor := decoded.Value.Group[0]
	if vendor.Attr.Name != "Broadband-Forum" {
		t.Fatalf("vendor block = %s, want Broadband-Forum", vendor.Attr.Name)
	}
	var sawACS, sawProv bool
	for _, sub := range vendor.Value.Group {
		switch sub.Attr.Name {
		case "ACS-URL":
			if string(sub.Value.Bytes) != "https://acs.example/cpe" && sub.Value.Str != "https://acs.example/cpe" {
				t.Fatalf("ACS-URL = %q / %q", sub.Value.Bytes, sub.Value.Str)
			}
			sawACS = true
		case "Provisioning-Code":
			if string(sub.Value.Bytes) != "ZONE-A" && sub.Value.Str != "ZONE-A" {
				t.Fatalf("Provisioning-Code = %q / %q", sub.Value.Bytes, sub.Value.Str)
			}
			sawProv = true
		}
	}
	if !sawACS || !sawProv {
		t.Fatalf("missing sub-options (ACS-URL=%v, Provisioning-Code=%v)", sawACS, sawProv)
	}
}

// TestDecodedOption43DecodeWithoutHintStaysOpaque confirms that, with no
// vendor hint, option 43 reaches the user as the FR-standard
// `Vendor-Specific-Options` opaque-octets attribute — i.e. no accidental
// guessing of vendor structure.
func TestDecodedOption43DecodeWithoutHintStaysOpaque(t *testing.T) {
	proto := loadV4(t)
	input := `Client-Hardware-Address = 02:00:00:00:00:01
Transaction-Id = 0x11223344
Message-Type = Discover
Decoded-Option-43.Broadband-Forum.ACS-URL = "https://acs.example/cpe"
`
	records, err := attrs.ReadList(strings.NewReader(input), proto)
	if err != nil {
		t.Fatalf("ReadList: %v", err)
	}
	wire, err := Encode(records[0], proto)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	pkt, err := Decode(wire, proto, "") // no hint
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	var sawDecoded bool
	var sawOpaque bool
	for _, p := range pkt.Pairs {
		if p.Attr == nil {
			continue
		}
		if p.Attr.Name == "Decoded-Option-43" {
			sawDecoded = true
		}
		if p.Attr.Name == "Vendor-Specific-Options" {
			sawOpaque = true
			// The opaque payload must be the same 25 bytes the encoder put on
			// the wire: 01 17 + 23 bytes of ACS-URL.
			want, _ := hex.DecodeString("0117" + "68747470733a2f2f6163732e6578616d706c652f637065")
			if !bytes.Equal(p.Value.Bytes, want) {
				t.Fatalf("Vendor-Specific-Options payload mismatch.\nwant: %s\ngot:  %s",
					hex.EncodeToString(want), hex.EncodeToString(p.Value.Bytes))
			}
		}
	}
	if sawDecoded {
		t.Fatal("Decoded-Option-43 must NOT appear when no hint is given")
	}
	if !sawOpaque {
		t.Fatal("Vendor-Specific-Options (opaque) missing in no-hint decode")
	}
}

// acmeDict is a tiny custom dictionary that introduces an Acme vendor block
// under Decoded-Option-43. It uses two sub-options to exercise both string
// and ipaddr leaves.
const acmeDict = `# Custom Acme vendor block under Decoded-Option-43.
# Demonstrates how an operator can teach dhcpdbg about a vendor's option 43
# sub-options without modifying the embedded FR tree.
ATTRIBUTE	Acme					276.42	tlv
ATTRIBUTE	Image-Server				.1	ipaddr
ATTRIBUTE	Image-Path				.2	string
`

// TestDecodedOption43RoundTripCustomVendor loads a custom dictionary that
// adds an `Acme` vendor block under Decoded-Option-43 and round-trips a
// packet through encode + hinted decode.
func TestDecodedOption43RoundTripCustomVendor(t *testing.T) {
	proto := loadV4Custom(t, map[string]string{"dictionary.acme": acmeDict})

	// Confirm the dictionary loaded the way we expect before exercising the codec.
	decoded, ok := proto.AttrByName("Decoded-Option-43")
	if !ok {
		t.Fatal("Decoded-Option-43 missing from custom-loaded protocol")
	}
	var acme *dict.Attr
	for _, c := range decoded.Children {
		if c.Name == "Acme" {
			acme = c
			break
		}
	}
	if acme == nil {
		t.Fatal("Decoded-Option-43.Acme not parsed into Children")
	}
	if len(acme.Children) != 2 {
		t.Fatalf("Acme.Children = %d, want 2", len(acme.Children))
	}

	input := `Client-Hardware-Address = 02:00:00:00:00:01
Transaction-Id = 0xdeadbeef
Message-Type = Discover
Decoded-Option-43.Acme.Image-Server = 198.51.100.7
Decoded-Option-43.Acme.Image-Path   = "/boot/cpe.img"
`
	records, err := attrs.ReadList(strings.NewReader(input), proto)
	if err != nil {
		t.Fatalf("ReadList: %v", err)
	}
	wire, err := Encode(records[0], proto)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// Expected wire: 0x2b, len, sub 1 (Image-Server, 4 bytes IP),
	// sub 2 (Image-Path, 13 bytes).
	// 01 04 c6 33 64 07  02 0d "/boot/cpe.img"
	wantPayload, _ := hex.DecodeString("0104c633640702" + "0d" + "2f626f6f742f6370652e696d67")
	if !bytes.Contains(wire, append([]byte{0x2b, byte(len(wantPayload))}, wantPayload...)) {
		t.Fatalf("custom-vendor option 43 not found.\nwantPayload: %s\nwire: %s",
			hex.EncodeToString(wantPayload), hex.EncodeToString(wire))
	}

	pkt, err := Decode(wire, proto, "Acme")
	if err != nil {
		t.Fatalf("Decode (hint=Acme): %v", err)
	}
	var dec *attrs.Pair
	for i := range pkt.Pairs {
		if pkt.Pairs[i].Attr != nil && pkt.Pairs[i].Attr.Name == "Decoded-Option-43" {
			dec = &pkt.Pairs[i]
			break
		}
	}
	if dec == nil {
		t.Fatal("Decoded-Option-43 missing after hinted decode")
	}
	if len(dec.Value.Group) != 1 || dec.Value.Group[0].Attr.Name != "Acme" {
		t.Fatalf("expected single Acme block, got %+v", dec.Value.Group)
	}
	var sawIP, sawPath bool
	for _, sub := range dec.Value.Group[0].Value.Group {
		switch sub.Attr.Name {
		case "Image-Server":
			if len(sub.Value.IPv4) != 4 || sub.Value.IPv4[0] != 198 || sub.Value.IPv4[1] != 51 ||
				sub.Value.IPv4[2] != 100 || sub.Value.IPv4[3] != 7 {
				t.Fatalf("Image-Server = %v", sub.Value.IPv4)
			}
			sawIP = true
		case "Image-Path":
			got := sub.Value.Str
			if got == "" {
				got = string(sub.Value.Bytes)
			}
			if got != "/boot/cpe.img" {
				t.Fatalf("Image-Path = %q", got)
			}
			sawPath = true
		}
	}
	if !sawIP || !sawPath {
		t.Fatalf("missing sub-options (Image-Server=%v, Image-Path=%v)", sawIP, sawPath)
	}
}

// TestDecodedOption43MultiVendorErrors confirms that supplying two vendor
// blocks in a single record is refused — option 43 has no PEN, so mixing
// vendors would silently corrupt the wire.
func TestDecodedOption43MultiVendorErrors(t *testing.T) {
	proto := loadV4Custom(t, map[string]string{"dictionary.acme": acmeDict})
	input := `Client-Hardware-Address = 02:00:00:00:00:01
Transaction-Id = 0xdeadbeef
Message-Type = Discover
Decoded-Option-43.Broadband-Forum.ACS-URL = "https://acs.example/cpe"
Decoded-Option-43.Acme.Image-Path         = "/boot/cpe.img"
`
	records, err := attrs.ReadList(strings.NewReader(input), proto)
	if err != nil {
		t.Fatalf("ReadList: %v", err)
	}
	_, err = Encode(records[0], proto)
	if err == nil {
		t.Fatal("expected Encode error for multi-vendor Decoded-Option-43, got nil")
	}
	if !strings.Contains(err.Error(), "Decoded-Option-43") || !strings.Contains(err.Error(), "exactly one vendor block expected") {
		t.Fatalf("error didn't mention multi-vendor mismatch: %v", err)
	}
}

// TestDecodedOption43UnknownVendorHint exercises the hint path: when the hint
// names a vendor that doesn't exist under Decoded-Option-43 in the loaded
// protocol, the option-43 payload silently falls through to opaque octets
// (the Vendor-Specific-Options leaf), so legacy traces still parse.
func TestDecodedOption43UnknownVendorHint(t *testing.T) {
	proto := loadV4(t)
	input := `Client-Hardware-Address = 02:00:00:00:00:01
Transaction-Id = 0x11223344
Message-Type = Discover
Decoded-Option-43.Broadband-Forum.ACS-URL = "https://acs.example/cpe"
`
	records, err := attrs.ReadList(strings.NewReader(input), proto)
	if err != nil {
		t.Fatalf("ReadList: %v", err)
	}
	wire, err := Encode(records[0], proto)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	pkt, err := Decode(wire, proto, "Nonexistent-Vendor")
	if err != nil {
		t.Fatalf("Decode (bad hint): %v", err)
	}
	var sawDecoded, sawOpaque bool
	for _, p := range pkt.Pairs {
		if p.Attr == nil {
			continue
		}
		if p.Attr.Name == "Decoded-Option-43" {
			sawDecoded = true
		}
		if p.Attr.Name == "Vendor-Specific-Options" {
			sawOpaque = true
		}
	}
	if sawDecoded {
		t.Fatal("Decoded-Option-43 surfaced despite unknown vendor hint")
	}
	if !sawOpaque {
		t.Fatal("Vendor-Specific-Options (opaque fallback) missing on unknown hint")
	}
}
