package info

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ludomikula/dhcpdbg/internal/dict"
)

// loadEmbedded returns the embedded DHCPv4 protocol — the baseline most
// tests run against.
func loadEmbedded(t *testing.T) *dict.Protocol {
	t.Helper()
	proto, err := dict.LoadDHCPv4()
	if err != nil {
		t.Fatalf("LoadDHCPv4: %v", err)
	}
	return proto
}

// loadWithCustom writes the given dictionary contents into a temp file and
// loads it on top of the embedded DHCPv4 tree.
func loadWithCustom(t *testing.T, name, body string) *dict.Protocol {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("WriteFile %s: %v", path, err)
	}
	proto, err := dict.LoadDHCPv4(dict.WithCustomDicts(path))
	if err != nil {
		t.Fatalf("LoadDHCPv4 custom: %v", err)
	}
	return proto
}

// TestListDictsEmbeddedHasExpectedSpread checks that ListDicts surfaces the
// embedded dictionary tree: at least the headline rfc2131 file (the bulk
// of DHCPv4 attrs) and the freeradius.internal file are present, and the
// header line announces a non-trivial file count.
func TestListDictsEmbeddedHasExpectedSpread(t *testing.T) {
	var buf bytes.Buffer
	if err := ListDicts(&buf, loadEmbedded(t), FormatText); err != nil {
		t.Fatalf("ListDicts: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "dhcpv4/dictionary.rfc2131") {
		t.Fatalf("expected rfc2131 in output, got:\n%s", out)
	}
	if !strings.Contains(out, "dhcpv4/dictionary.freeradius.internal") {
		t.Fatalf("expected freeradius.internal in output, got:\n%s", out)
	}
	if !strings.Contains(out, "LOAD ORDER") || !strings.Contains(out, "ATTRS") {
		t.Fatalf("expected table header (LOAD ORDER/ATTRS) in output, got:\n%s", out)
	}
}

// TestListDictsAttrCountsAreExact confirms the per-file ATTRS column adds
// up to the protocol's total attribute count. Per-file counts come from
// each Attr's SourceFile stamp, so the sum is the canonical truth.
func TestListDictsAttrCountsAreExact(t *testing.T) {
	proto := loadEmbedded(t)
	counts := attrCountsBySource(proto)
	sum := 0
	for _, n := range counts {
		sum += n
	}
	wantSum := countTopLevelAttrs(proto) + countInternalAttrs(proto) + countVendorAttrs(proto)
	if sum != wantSum {
		t.Fatalf("per-file attr counts sum to %d, want %d", sum, wantSum)
	}
}

// TestListDictsCustomAppended verifies that layering a custom dictionary on
// top of the embedded tree adds rows to --list-dicts and stamps the new
// attrs with the custom file's name.
func TestListDictsCustomAppended(t *testing.T) {
	proto := loadWithCustom(t, "dictionary.acme", `
VENDOR Acme-Networks 99999
BEGIN-VENDOR Acme-Networks
ATTRIBUTE Custom-Option 1 string
ATTRIBUTE Auth-Token    2 octets
END-VENDOR Acme-Networks
`)
	var buf bytes.Buffer
	if err := ListDicts(&buf, proto, FormatText); err != nil {
		t.Fatalf("ListDicts: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "custom:") {
		t.Fatalf("expected custom: source label in output, got:\n%s", out)
	}
	if !strings.Contains(out, "dictionary.acme") {
		t.Fatalf("expected dictionary.acme in output, got:\n%s", out)
	}
}

// TestListDictsJSONShape decodes the JSON output and validates the expected
// top-level structure.
func TestListDictsJSONShape(t *testing.T) {
	proto := loadEmbedded(t)
	var buf bytes.Buffer
	if err := ListDicts(&buf, proto, FormatJSON); err != nil {
		t.Fatalf("ListDicts json: %v", err)
	}
	var out struct {
		Protocol string `json:"protocol"`
		Files    []struct {
			LoadOrder int    `json:"load_order"`
			Source    string `json:"source"`
			Path      string `json:"path"`
			Attrs     int    `json:"attrs"`
		} `json:"files"`
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("json.Unmarshal: %v\n%s", err, buf.String())
	}
	if out.Protocol != "DHCPv4" {
		t.Fatalf("Protocol = %q, want DHCPv4", out.Protocol)
	}
	if len(out.Files) < 2 {
		t.Fatalf("Files = %d, want at least 2", len(out.Files))
	}
	if out.Files[0].LoadOrder != 1 {
		t.Fatalf("first LoadOrder = %d, want 1", out.Files[0].LoadOrder)
	}
}

// TestPrintDictMentionsBroadbandForumChildren spot-checks the three-level
// rendering of Decoded-Option-43 → Broadband-Forum → ACS-URL — the same
// path the option-43 codec uses.
func TestPrintDictMentionsBroadbandForumChildren(t *testing.T) {
	var buf bytes.Buffer
	if err := PrintDict(&buf, loadEmbedded(t), nil, FormatText); err != nil {
		t.Fatalf("PrintDict: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Decoded-Option-43") {
		t.Fatalf("missing Decoded-Option-43 in dump:\n%s", out)
	}
	if !strings.Contains(out, "Broadband-Forum") {
		t.Fatalf("missing Broadband-Forum in dump:\n%s", out)
	}
	if !strings.Contains(out, "ACS-URL") {
		t.Fatalf("missing ACS-URL in dump:\n%s", out)
	}
}

// TestPrintDictMessageTypeEnumValues confirms the Details block for
// Message-Type lists every standard DHCPv4 message-type enum.
func TestPrintDictMessageTypeEnumValues(t *testing.T) {
	var buf bytes.Buffer
	if err := PrintDict(&buf, loadEmbedded(t), nil, FormatText); err != nil {
		t.Fatalf("PrintDict: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"### Message-Type (53)", "Discover", "Offer", "Request", "Ack", "NAK", "Release", "Inform"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in Message-Type details, got:\n%s", want, out)
		}
	}
}

// TestPrintDictRelayAgentSubOptions checks that option 82's sub-options
// (Circuit-Id, Remote-Id) are visible in the Relay-Agent-Information
// Details block.
func TestPrintDictRelayAgentSubOptions(t *testing.T) {
	var buf bytes.Buffer
	if err := PrintDict(&buf, loadEmbedded(t), nil, FormatText); err != nil {
		t.Fatalf("PrintDict: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"Relay-Agent-Information", "Circuit-Id", "Remote-Id"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in Relay-Agent details, got:\n%s", want, out)
		}
	}
}

// TestPrintDictSingleVendorFilter confirms that --vendor=Name restricts
// output to the named vendor block.
func TestPrintDictSingleVendorFilter(t *testing.T) {
	var buf bytes.Buffer
	if err := PrintDict(&buf, loadEmbedded(t), []string{"ADSL-Forum"}, FormatText); err != nil {
		t.Fatalf("PrintDict: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "## Vendor: ADSL-Forum") {
		t.Fatalf("expected ADSL-Forum header, got:\n%s", out)
	}
	if !strings.Contains(out, "ACS-URL") {
		t.Fatalf("expected ACS-URL inside ADSL-Forum block, got:\n%s", out)
	}
	if strings.Contains(out, "## Top-level options") {
		t.Fatalf("vendor filter must not emit top-level table, got:\n%s", out)
	}
	if strings.Contains(out, "## Vendor: CableLabs") {
		t.Fatalf("vendor filter leaked other vendor blocks, got:\n%s", out)
	}
}

// TestPrintDictUnknownVendorErrors confirms that an unknown vendor name
// returns an error listing the available vendors.
func TestPrintDictUnknownVendorErrors(t *testing.T) {
	err := PrintDict(&bytes.Buffer{}, loadEmbedded(t), []string{"Nope"}, FormatText)
	if err == nil {
		t.Fatal("expected error for unknown vendor, got nil")
	}
	if !strings.Contains(err.Error(), "unknown vendor") || !strings.Contains(err.Error(), "ADSL-Forum") {
		t.Fatalf("error doesn't list available vendors: %v", err)
	}
}

// TestPrintDictCustomVendorShowsSourceFile loads a custom dictionary that
// adds a vendor block under Decoded-Option-43 and verifies the dump
// labels its source as the custom file's basename.
func TestPrintDictCustomVendorShowsSourceFile(t *testing.T) {
	proto := loadWithCustom(t, "dictionary.acme", `
ATTRIBUTE Acme    276.42 tlv
ATTRIBUTE Image-Server  .1 ipaddr
ATTRIBUTE Image-Path    .2 string
`)
	var buf bytes.Buffer
	if err := PrintDict(&buf, proto, nil, FormatText); err != nil {
		t.Fatalf("PrintDict: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Decoded-Option-43") || !strings.Contains(out, "Acme") {
		t.Fatalf("custom Acme block not present in dump:\n%s", out)
	}
	if !strings.Contains(out, "custom:dictionary.acme") {
		t.Fatalf("custom source label missing, got:\n%s", out)
	}
}

// TestPrintDictJSONShape decodes the JSON tree and checks the expected
// top-level structure.
func TestPrintDictJSONShape(t *testing.T) {
	var buf bytes.Buffer
	if err := PrintDict(&buf, loadEmbedded(t), nil, FormatJSON); err != nil {
		t.Fatalf("PrintDict json: %v", err)
	}
	var out struct {
		Protocol           string `json:"protocol"`
		ProtocolCode       uint32 `json:"protocol_code"`
		TopLevelAttributes []struct {
			Code uint32 `json:"code"`
			Name string `json:"name"`
		} `json:"top_level_attributes"`
		Vendors []struct {
			Name string `json:"name"`
			PEN  uint32 `json:"pen"`
		} `json:"vendors"`
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("json.Unmarshal: %v\n%s", err, buf.String())
	}
	if out.Protocol != "DHCPv4" || out.ProtocolCode != 2 {
		t.Fatalf("Protocol/Code = %q/%d, want DHCPv4/2", out.Protocol, out.ProtocolCode)
	}
	if len(out.TopLevelAttributes) < 100 {
		t.Fatalf("TopLevelAttributes = %d, want >= 100", len(out.TopLevelAttributes))
	}
	var sawSubnetMask bool
	for _, a := range out.TopLevelAttributes {
		if a.Name == "Subnet-Mask" && a.Code == 1 {
			sawSubnetMask = true
			break
		}
	}
	if !sawSubnetMask {
		t.Fatalf("missing Subnet-Mask (code 1) in TopLevelAttributes")
	}
	var sawADSL bool
	for _, v := range out.Vendors {
		if v.Name == "ADSL-Forum" && v.PEN == 3561 {
			sawADSL = true
			break
		}
	}
	if !sawADSL {
		t.Fatalf("missing ADSL-Forum (PEN 3561) in Vendors")
	}
}

// TestPrintDictV6 sanity-checks that the same code paths work against
// DHCPv6 — the dictionary tree has different shape (no internal Decoded-
// Option-43, but lots of IA-* containers).
func TestPrintDictV6(t *testing.T) {
	proto, err := dict.LoadDHCPv6()
	if err != nil {
		t.Fatalf("LoadDHCPv6: %v", err)
	}
	var buf bytes.Buffer
	if err := PrintDict(&buf, proto, nil, FormatText); err != nil {
		t.Fatalf("PrintDict v6: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"DHCPv6 dictionary", "IA-NA", "Client-ID", "## Vendors"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in v6 dump, got:\n%s", want, out)
		}
	}
}

// TestEmbeddedTail covers the embedded path → short-tag transformation
// the SOURCE column uses.
func TestEmbeddedTail(t *testing.T) {
	cases := map[string]string{
		"dhcpv4/dictionary.rfc2131":              "rfc2131",
		"dhcpv4/dictionary.freeradius.internal":  "freeradius.internal",
		"dhcpv4/dictionary":                      "root",
		"dhcpv6/dictionary.adsl_forum":           "adsl_forum",
	}
	for in, want := range cases {
		if got := embeddedTail(in); got != want {
			t.Errorf("embeddedTail(%q) = %q, want %q", in, got, want)
		}
	}
}
