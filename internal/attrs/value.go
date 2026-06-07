// Package attrs implements the "FreeRADIUS attribute notation" layer:
// parsing `Attribute = value` input into typed values, formatting typed
// values back to that notation, and a small typed value union (Value).
//
// The package is wire-codec agnostic — it doesn't know about DHCPv4 or
// DHCPv6 framing. The wire4 / wire6 packages consume []Pair lists and turn
// them into bytes.
package attrs

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/ludomikula/dhcpdbg/internal/dict"
)

// Value is a discriminated typed value. Exactly one of the fields matching
// Type is meaningful.
type Value struct {
	Type   dict.AttrType
	Uint   uint64    // uint8/16/32/64, bool (0/1), date, time_delta, attribute
	Str    string    // string
	Bytes  []byte    // octets, ether, ifid, ipv4prefix, ipv6prefix, struct/group/tlv/vsa raw
	IPv4   net.IP    // ipaddr (4 bytes)
	IPv6   net.IP    // ipv6addr (16 bytes)
}

// Pair couples a dictionary attribute with a value.
type Pair struct {
	Attr  *dict.Attr
	Value Value
}

// Parse turns a textual value v into a Value of type at, using the enum table
// from a (for resolving named enum values like Message-Type = Discover). When
// a has type "attribute" (Parameter-Request-List / Option-Request) we also
// try resolving v against proto's attribute table — so users can write
// `Option-Request = Domain-Name-Server` instead of the raw code.
func Parse(a *dict.Attr, v string, proto *dict.Protocol) (Value, error) {
	v = strings.TrimSpace(v)
	// Strip surrounding double quotes for string-like types.
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		v = v[1 : len(v)-1]
	}
	switch a.Type {
	case dict.TypeUint8, dict.TypeUint16, dict.TypeUint32, dict.TypeUint64,
		dict.TypeDate, dict.TypeTimeDelta, dict.TypeAttribute:
		// Try enum first.
		if a.EnumByName != nil {
			if n, ok := a.EnumByName[v]; ok {
				return Value{Type: a.Type, Uint: n}, nil
			}
		}
		// For TypeAttribute (PRL / Option-Request) accept attribute names.
		if a.Type == dict.TypeAttribute && proto != nil {
			if ref, ok := proto.AttrByName(v); ok {
				return Value{Type: a.Type, Uint: uint64(ref.Code)}, nil
			}
		}
		// Accept 0x / 0 prefixes via ParseUint base 0.
		n, err := strconv.ParseUint(v, 0, 64)
		if err != nil {
			return Value{}, fmt.Errorf("attribute %s: bad integer %q", a.Name, v)
		}
		return Value{Type: a.Type, Uint: n}, nil

	case dict.TypeBool:
		switch strings.ToLower(v) {
		case "1", "true", "yes", "on":
			return Value{Type: dict.TypeBool, Uint: 1}, nil
		case "0", "false", "no", "off":
			return Value{Type: dict.TypeBool, Uint: 0}, nil
		}
		return Value{}, fmt.Errorf("attribute %s: bad bool %q", a.Name, v)

	case dict.TypeString:
		return Value{Type: dict.TypeString, Str: v}, nil

	case dict.TypeOctets, dict.TypeStruct, dict.TypeTLV, dict.TypeGroup, dict.TypeVSA, dict.TypeUnion:
		b, err := parseOctets(v)
		if err != nil {
			return Value{}, fmt.Errorf("attribute %s: %v", a.Name, err)
		}
		return Value{Type: a.Type, Bytes: b}, nil

	case dict.TypeIPv4Addr:
		ip := net.ParseIP(v)
		if ip == nil || ip.To4() == nil {
			return Value{}, fmt.Errorf("attribute %s: bad IPv4 %q", a.Name, v)
		}
		return Value{Type: dict.TypeIPv4Addr, IPv4: ip.To4()}, nil

	case dict.TypeIPv6Addr:
		ip := net.ParseIP(v)
		if ip == nil || ip.To16() == nil || ip.To4() != nil {
			return Value{}, fmt.Errorf("attribute %s: bad IPv6 %q", a.Name, v)
		}
		return Value{Type: dict.TypeIPv6Addr, IPv6: ip.To16()}, nil

	case dict.TypeEther:
		b, err := parseEther(v)
		if err != nil {
			return Value{}, fmt.Errorf("attribute %s: %v", a.Name, err)
		}
		return Value{Type: dict.TypeEther, Bytes: b}, nil

	case dict.TypeIfid:
		b, err := parseOctets("0x" + strings.ReplaceAll(v, ":", ""))
		if err != nil || len(b) != 8 {
			return Value{}, fmt.Errorf("attribute %s: bad ifid %q", a.Name, v)
		}
		return Value{Type: dict.TypeIfid, Bytes: b}, nil

	case dict.TypeIPv4Prefix:
		b, err := parsePrefix(v, 4)
		if err != nil {
			return Value{}, fmt.Errorf("attribute %s: %v", a.Name, err)
		}
		return Value{Type: dict.TypeIPv4Prefix, Bytes: b}, nil

	case dict.TypeIPv6Prefix:
		b, err := parsePrefix(v, 16)
		if err != nil {
			return Value{}, fmt.Errorf("attribute %s: %v", a.Name, err)
		}
		return Value{Type: dict.TypeIPv6Prefix, Bytes: b}, nil
	}
	return Value{}, fmt.Errorf("attribute %s: unsupported type %s", a.Name, a.Type)
}

// parseOctets accepts:
//   - "0x<hex>"     — strict hex blob
//   - "<hex>"       — bare hex if even-length and all hex
//   - quoted string — already stripped by caller; falls back to UTF-8 bytes
func parseOctets(v string) ([]byte, error) {
	s := strings.TrimSpace(v)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
		s = strings.ReplaceAll(s, ":", "")
		s = strings.ReplaceAll(s, " ", "")
		return hex.DecodeString(s)
	}
	// Plain string fallback — useful for octets attributes that carry text
	// (Client-Identifier, Vendor-Class-Identifier, ...).
	return []byte(v), nil
}

func parseEther(v string) ([]byte, error) {
	s := strings.ReplaceAll(v, ":", "")
	s = strings.ReplaceAll(s, "-", "")
	if len(s) != 12 {
		return nil, fmt.Errorf("bad ether %q (need 6 octets)", v)
	}
	return hex.DecodeString(s)
}

// parsePrefix accepts "<ip>/<len>" and returns [len, addr...] wire form used by
// FreeRADIUS for ipv4prefix / ipv6prefix.
func parsePrefix(v string, addrLen int) ([]byte, error) {
	slash := strings.IndexByte(v, '/')
	if slash < 0 {
		return nil, fmt.Errorf("bad prefix %q (need addr/len)", v)
	}
	ipStr := v[:slash]
	plenStr := v[slash+1:]
	plen, err := strconv.Atoi(plenStr)
	if err != nil {
		return nil, fmt.Errorf("bad prefix length %q", plenStr)
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("bad prefix IP %q", ipStr)
	}
	var raw []byte
	if addrLen == 4 {
		raw = ip.To4()
		if raw == nil || plen > 32 {
			return nil, fmt.Errorf("bad IPv4 prefix %q", v)
		}
	} else {
		raw = ip.To16()
		if raw == nil || plen > 128 {
			return nil, fmt.Errorf("bad IPv6 prefix %q", v)
		}
	}
	out := make([]byte, 1+addrLen)
	out[0] = byte(plen)
	copy(out[1:], raw)
	return out, nil
}

// Format renders a Value back into the FreeRADIUS attribute-list notation
// shown in DHCP-SPEC.md examples.
func Format(a *dict.Attr, v Value) string {
	switch v.Type {
	case dict.TypeUint8, dict.TypeUint16, dict.TypeUint32, dict.TypeUint64,
		dict.TypeDate, dict.TypeTimeDelta, dict.TypeAttribute:
		if a.EnumByValue != nil {
			if name, ok := a.EnumByValue[v.Uint]; ok {
				return name
			}
		}
		return strconv.FormatUint(v.Uint, 10)
	case dict.TypeBool:
		if v.Uint != 0 {
			return "yes"
		}
		return "no"
	case dict.TypeString:
		return strconv.Quote(v.Str)
	case dict.TypeIPv4Addr:
		return net.IP(v.IPv4).String()
	case dict.TypeIPv6Addr:
		return net.IP(v.IPv6).String()
	case dict.TypeEther:
		return formatEther(v.Bytes)
	case dict.TypeIPv4Prefix, dict.TypeIPv6Prefix:
		if len(v.Bytes) == 0 {
			return "0x"
		}
		plen := int(v.Bytes[0])
		ip := net.IP(v.Bytes[1:]).String()
		return fmt.Sprintf("%s/%d", ip, plen)
	default:
		return "0x" + hex.EncodeToString(v.Bytes)
	}
}

func formatEther(b []byte) string {
	if len(b) != 6 {
		return "0x" + hex.EncodeToString(b)
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}
