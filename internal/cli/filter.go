package cli

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/ludomikula/dhcpdbg/internal/attrs"
	"github.com/ludomikula/dhcpdbg/internal/dict"
	"github.com/ludomikula/dhcpdbg/internal/pcap"
)

// Filter matches a captured DHCP packet against a comma-separated list of
// `key=value` clauses. All clauses must hold for the packet to match (AND
// semantics). Use a single empty Filter (zero value) to disable filtering.
//
// Reserved keys (case-insensitive on the LHS):
//
//	family      v4 | v6
//	src         ip[:port]
//	dst         ip[:port]
//	msg-type    DHCPv4 Message-Type or DHCPv6 Packet-Type name (case-insensitive)
//
// Any other LHS is treated as a dictionary attribute name; the matcher
// renders the decoded value via attrs.Format and compares it (case-
// sensitive, exact match) to the RHS. Use double-quoted strings if the
// RHS contains a comma or whitespace.
//
// Examples:
//
//	--filter 'msg-type=Discover'
//	--filter 'family=v4,src=10.0.0.1'
//	--filter 'Hostname="lab-host"'
//	--filter 'Vendor-Class-Identifier="udhcp 1.20"'
type Filter struct {
	family  string // "", "v4", "v6"
	src     string // empty = no constraint; "ip" or "ip:port"
	dst     string
	msgType string // empty = no constraint; e.g. "Discover"
	// attrs maps a dictionary attribute name to the required formatted
	// value. Empty = no attribute constraints.
	attrs map[string]string
}

// ParseFilter parses a `key=value[,key=value...]` expression into a Filter.
// An empty string returns a zero Filter (matches everything).
func ParseFilter(expr string) (Filter, error) {
	var f Filter
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return f, nil
	}
	clauses, err := splitFilterClauses(expr)
	if err != nil {
		return f, err
	}
	for _, c := range clauses {
		eq := strings.IndexByte(c, '=')
		if eq <= 0 {
			return f, fmt.Errorf("filter clause %q: expected key=value", c)
		}
		key := strings.TrimSpace(c[:eq])
		val := strings.TrimSpace(c[eq+1:])
		val = unquoteIfQuoted(val)
		switch strings.ToLower(key) {
		case "family":
			switch strings.ToLower(val) {
			case "v4", "4", "dhcpv4":
				f.family = "v4"
			case "v6", "6", "dhcpv6":
				f.family = "v6"
			default:
				return f, fmt.Errorf("filter family=%q: want v4 or v6", val)
			}
		case "src":
			f.src = val
		case "dst":
			f.dst = val
		case "msg-type", "msgtype", "message-type":
			f.msgType = val
		default:
			if f.attrs == nil {
				f.attrs = map[string]string{}
			}
			f.attrs[key] = val
		}
	}
	return f, nil
}

// splitFilterClauses splits on `,` outside of double-quoted spans. Quotes
// can be escaped with a leading backslash inside the string.
func splitFilterClauses(s string) ([]string, error) {
	var out []string
	var cur strings.Builder
	inQ := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s):
			cur.WriteByte(s[i+1])
			i++
		case c == '"':
			inQ = !inQ
			cur.WriteByte(c)
		case c == ',' && !inQ:
			out = append(out, strings.TrimSpace(cur.String()))
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	if inQ {
		return nil, fmt.Errorf("filter has unterminated double-quoted string")
	}
	last := strings.TrimSpace(cur.String())
	if last != "" {
		out = append(out, last)
	}
	return out, nil
}

func unquoteIfQuoted(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		if u, err := strconv.Unquote(s); err == nil {
			return u
		}
	}
	return s
}

// IsZero reports whether the filter has any constraints. A zero filter
// matches every frame so callers can skip the per-packet match call.
func (f Filter) IsZero() bool {
	return f.family == "" && f.src == "" && f.dst == "" && f.msgType == "" && len(f.attrs) == 0
}

// Match returns true if the frame's metadata (family, src/dst) AND its
// decoded attribute list pass every clause. proto is used to look up
// dictionary attributes for attribute-name clauses; pass the protocol
// matching the frame's family.
func (f Filter) Match(frame *pcap.Frame, pairs []attrs.Pair, proto *dict.Protocol) bool {
	if f.IsZero() {
		return true
	}
	if f.family != "" {
		if (f.family == "v4" && frame.Family != pcap.FamilyV4) ||
			(f.family == "v6" && frame.Family != pcap.FamilyV6) {
			return false
		}
	}
	if f.src != "" && !endpointMatches(f.src, frame.SrcIP.String(), frame.SrcPort) {
		return false
	}
	if f.dst != "" && !endpointMatches(f.dst, frame.DstIP.String(), frame.DstPort) {
		return false
	}
	if f.msgType != "" && !msgTypeMatches(f.msgType, pairs) {
		return false
	}
	for name, want := range f.attrs {
		if !attrMatches(name, want, pairs, proto) {
			return false
		}
	}
	return true
}

// endpointMatches checks if a `ip[:port]` clause matches a (host, port)
// pair from a Frame. Either side of the colon can be omitted.
func endpointMatches(clause, host string, port uint16) bool {
	if i := strings.LastIndexByte(clause, ':'); i >= 0 && !strings.Contains(clause[:i], "]") {
		// IPv4-style host:port. (IPv6 literals would need [..]:port; we
		// recognise that via the absence of "]" in the head.)
		wantHost := clause[:i]
		wantPort := clause[i+1:]
		if wantHost != "" && wantHost != host {
			return false
		}
		if wantPort != "" {
			n, err := strconv.Atoi(wantPort)
			if err != nil || uint16(n) != port {
				return false
			}
		}
		return true
	}
	// Pure IP — port is unconstrained.
	return clause == host
}

// msgTypeMatches scans the decoded pair list for a Message-Type or
// Packet-Type attribute matching the wanted enum name (case-insensitive).
func msgTypeMatches(want string, pairs []attrs.Pair) bool {
	want = strings.ToLower(want)
	for _, p := range pairs {
		if p.Attr == nil {
			continue
		}
		switch p.Attr.Name {
		case "Message-Type", "Packet-Type":
			if name, ok := p.Attr.EnumByValue[p.Value.Uint]; ok {
				if strings.ToLower(name) == want {
					return true
				}
			}
			if strconv.FormatUint(p.Value.Uint, 10) == want {
				return true
			}
		}
	}
	return false
}

// attrMatches scans the decoded pair list for any attribute named `name`
// whose formatted value equals `want`. Multiple instances (arrays) are
// OR'd: a match on any instance satisfies the clause.
func attrMatches(name, want string, pairs []attrs.Pair, proto *dict.Protocol) bool {
	for _, p := range pairs {
		if p.Attr == nil {
			continue
		}
		if p.Attr.Name != name {
			continue
		}
		got := attrs.Format(p.Attr, p.Value)
		if got == want {
			return true
		}
		// Tolerate quoted-string vs bare-string: "lab-host" vs lab-host.
		if unquoteIfQuoted(got) == want {
			return true
		}
	}
	return false
}
