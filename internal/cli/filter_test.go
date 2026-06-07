package cli

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ludomikula/dhcpdbg/internal/attrs"
	"github.com/ludomikula/dhcpdbg/internal/dict"
	"github.com/ludomikula/dhcpdbg/internal/pcap"
)

// dhcpv4 returns a quickly-loaded DHCPv4 protocol for filter-match tests.
func dhcpv4(t *testing.T) *dict.Protocol {
	t.Helper()
	proto, err := dict.LoadDHCPv4()
	if err != nil {
		t.Fatalf("LoadDHCPv4: %v", err)
	}
	return proto
}

func makeFrame(family pcap.Family, src, dst string, sp, dp uint16) *pcap.Frame {
	return &pcap.Frame{
		Timestamp: time.Now(),
		Family:    family,
		SrcIP:     net.ParseIP(src),
		DstIP:     net.ParseIP(dst),
		SrcPort:   sp,
		DstPort:   dp,
	}
}

// makeDiscoverPairs returns a synthetic pair list approximating a
// DHCPDISCOVER (Message-Type=Discover plus Hostname="lab-host").
func makeDiscoverPairs(proto *dict.Protocol) []attrs.Pair {
	mt, _ := proto.AttrByName("Message-Type")
	host, _ := proto.AttrByName("Hostname")
	return []attrs.Pair{
		{Attr: mt, Value: attrs.Value{Type: mt.Type, Uint: 1}},
		{Attr: host, Value: attrs.Value{Type: dict.TypeString, Str: "lab-host"}},
	}
}

// TestParseFilterClauses exercises the splitter for both unquoted and
// quoted RHS values.
func TestParseFilterClauses(t *testing.T) {
	cases := map[string]Filter{
		"":                       {},
		"family=v4":              {family: "v4"},
		"family=v6":              {family: "v6"},
		"msg-type=Discover":      {msgType: "Discover"},
		"src=10.0.0.1":           {src: "10.0.0.1"},
		"src=10.0.0.1:68":        {src: "10.0.0.1:68"},
		"Hostname=lab-host":      {attrs: map[string]string{"Hostname": "lab-host"}},
		"Hostname=\"with,comma\"": {attrs: map[string]string{"Hostname": "with,comma"}},
		"family=v4,msg-type=Discover": {
			family:  "v4",
			msgType: "Discover",
		},
	}
	for in, want := range cases {
		got, err := ParseFilter(in)
		if err != nil {
			t.Errorf("ParseFilter(%q) error: %v", in, err)
			continue
		}
		if got.family != want.family || got.src != want.src || got.dst != want.dst || got.msgType != want.msgType {
			t.Errorf("ParseFilter(%q) = %+v, want %+v", in, got, want)
		}
		if len(want.attrs) != len(got.attrs) {
			t.Errorf("ParseFilter(%q) attrs len = %d, want %d", in, len(got.attrs), len(want.attrs))
		}
		for k, v := range want.attrs {
			if got.attrs[k] != v {
				t.Errorf("ParseFilter(%q) attrs[%s] = %q, want %q", in, k, got.attrs[k], v)
			}
		}
	}
}

// TestParseFilterErrors verifies clear errors for malformed input.
func TestParseFilterErrors(t *testing.T) {
	bad := []string{
		"family=hf",  // unknown family
		"=value",     // missing key
		`x="oops`,    // unterminated quote
	}
	for _, in := range bad {
		if _, err := ParseFilter(in); err == nil {
			t.Errorf("ParseFilter(%q) expected error", in)
		}
	}
}

// TestFilterMatchFamily — the family clause narrows by frame.Family.
func TestFilterMatchFamily(t *testing.T) {
	proto := dhcpv4(t)
	pairs := makeDiscoverPairs(proto)
	v4Frame := makeFrame(pcap.FamilyV4, "10.0.0.1", "255.255.255.255", 68, 67)
	v6Frame := makeFrame(pcap.FamilyV6, "fe80::1", "ff02::1:2", 546, 547)

	f, _ := ParseFilter("family=v4")
	if !f.Match(v4Frame, pairs, proto) {
		t.Fatal("v4 frame should match family=v4")
	}
	if f.Match(v6Frame, nil, proto) {
		t.Fatal("v6 frame should NOT match family=v4")
	}
}

// TestFilterMatchEndpoints — src/dst with optional ports.
func TestFilterMatchEndpoints(t *testing.T) {
	proto := dhcpv4(t)
	pairs := makeDiscoverPairs(proto)
	frame := makeFrame(pcap.FamilyV4, "10.0.0.1", "255.255.255.255", 68, 67)

	cases := map[string]bool{
		"src=10.0.0.1":             true,
		"src=10.0.0.1:68":          true,
		"src=10.0.0.1:67":          false,
		"dst=255.255.255.255":      true,
		"dst=255.255.255.255:67":   true,
		"dst=10.0.0.1":             false,
		"src=10.0.0.1,dst=255.255.255.255:67": true,
	}
	for expr, want := range cases {
		f, err := ParseFilter(expr)
		if err != nil {
			t.Fatalf("ParseFilter(%q): %v", expr, err)
		}
		got := f.Match(frame, pairs, proto)
		if got != want {
			t.Errorf("Match(%q) = %v, want %v", expr, got, want)
		}
	}
}

// TestFilterMatchMsgType — msg-type uses the dictionary's enum name.
func TestFilterMatchMsgType(t *testing.T) {
	proto := dhcpv4(t)
	pairs := makeDiscoverPairs(proto)
	frame := makeFrame(pcap.FamilyV4, "10.0.0.1", "10.0.0.2", 68, 67)
	for expr, want := range map[string]bool{
		"msg-type=Discover": true,
		"msg-type=discover": true, // case-insensitive
		"msg-type=Offer":    false,
		"msg-type=1":        true, // numeric match too
	} {
		f, err := ParseFilter(expr)
		if err != nil {
			t.Fatalf("ParseFilter(%q): %v", expr, err)
		}
		got := f.Match(frame, pairs, proto)
		if got != want {
			t.Errorf("Match(%q) = %v, want %v", expr, got, want)
		}
	}
}

// TestFilterMatchAttribute — arbitrary attribute name on the LHS, exact
// formatted value on the RHS.
func TestFilterMatchAttribute(t *testing.T) {
	proto := dhcpv4(t)
	pairs := makeDiscoverPairs(proto)
	frame := makeFrame(pcap.FamilyV4, "10.0.0.1", "10.0.0.2", 68, 67)

	f, _ := ParseFilter(`Hostname=lab-host`)
	if !f.Match(frame, pairs, proto) {
		t.Fatal("Hostname=lab-host should match")
	}
	f, _ = ParseFilter(`Hostname="lab-host"`)
	if !f.Match(frame, pairs, proto) {
		t.Fatal("Hostname=\"lab-host\" should match (quoted unquotes)")
	}
	f, _ = ParseFilter(`Hostname=other`)
	if f.Match(frame, pairs, proto) {
		t.Fatal("Hostname=other should NOT match")
	}
}

// TestFilterZeroMatchesEverything — a zero-value Filter passes any frame.
func TestFilterZeroMatchesEverything(t *testing.T) {
	proto := dhcpv4(t)
	frame := makeFrame(pcap.FamilyV4, "1.1.1.1", "2.2.2.2", 68, 67)
	f := Filter{}
	if !f.Match(frame, nil, proto) {
		t.Fatal("zero filter should match everything")
	}
}

// TestParseFilterRejectsUnknownFamily ensures a clear error mentions the
// invalid value.
func TestParseFilterRejectsUnknownFamily(t *testing.T) {
	_, err := ParseFilter("family=v9")
	if err == nil || !strings.Contains(err.Error(), "family") {
		t.Fatalf("expected family-error, got %v", err)
	}
}
