// Package dict implements a pragmatic parser for the FreeRADIUS v4 dictionary
// grammar, scoped to what dhcpdbg needs: load the DHCPv4 and DHCPv6 protocol
// dictionaries and answer attribute name<->number lookups, type lookups, and
// VALUE enum lookups for the encoder/decoder.
//
// The full v4 grammar (struct/MEMBER nesting, key=, clone=, union, vsa) is
// recognised but only partially modeled. For dhcpdbg we treat structured
// attributes (Client-ID, IA-NA, Vendor-Opts, ...) as opaque octets by default;
// the user can still craft them by passing a hex blob, and the decoder prints
// them as hex. This is documented in DHCP-SPEC.md as the debug-tool default.
package dict

import "fmt"

// AttrType is the wire-encoding type of an attribute.
type AttrType int

const (
	TypeUnknown AttrType = iota
	TypeOctets
	TypeString
	TypeUint8
	TypeUint16
	TypeUint32
	TypeUint64
	TypeBool
	TypeIPv4Addr
	TypeIPv6Addr
	TypeIPv4Prefix
	TypeIPv6Prefix
	TypeEther
	TypeIfid
	TypeDate
	TypeTimeDelta
	// TypeAttribute is the "attribute" type — a value that is itself a 1-byte
	// attribute number (used for Parameter-Request-List and DHCPv6 Option-Request).
	TypeAttribute
	// TypeStruct, TypeTLV, TypeGroup, TypeVSA, TypeUnion are container types.
	// For dhcpdbg we model them as a category and let the encoder/decoder
	// special-case the few well-known structured DHCPv6 attributes; everything
	// else falls through as opaque octets.
	TypeStruct
	TypeTLV
	TypeGroup
	TypeVSA
	TypeUnion
)

func (t AttrType) String() string {
	switch t {
	case TypeOctets:
		return "octets"
	case TypeString:
		return "string"
	case TypeUint8:
		return "uint8"
	case TypeUint16:
		return "uint16"
	case TypeUint32:
		return "uint32"
	case TypeUint64:
		return "uint64"
	case TypeBool:
		return "bool"
	case TypeIPv4Addr:
		return "ipaddr"
	case TypeIPv6Addr:
		return "ipv6addr"
	case TypeIPv4Prefix:
		return "ipv4prefix"
	case TypeIPv6Prefix:
		return "ipv6prefix"
	case TypeEther:
		return "ether"
	case TypeIfid:
		return "ifid"
	case TypeDate:
		return "date"
	case TypeTimeDelta:
		return "time_delta"
	case TypeAttribute:
		return "attribute"
	case TypeStruct:
		return "struct"
	case TypeTLV:
		return "tlv"
	case TypeGroup:
		return "group"
	case TypeVSA:
		return "vsa"
	case TypeUnion:
		return "union"
	}
	return "unknown"
}

// ParseType maps a v4-dictionary type token to an AttrType. Unrecognised
// tokens become TypeUnknown — the caller decides whether that's fatal.
func ParseType(tok string) AttrType {
	switch tok {
	case "octets":
		return TypeOctets
	case "string":
		return TypeString
	case "byte", "uint8":
		return TypeUint8
	case "short", "uint16":
		return TypeUint16
	case "integer", "uint32", "signed":
		return TypeUint32
	case "uint64", "integer64":
		return TypeUint64
	case "bool":
		return TypeBool
	case "ipaddr", "ipv4addr":
		return TypeIPv4Addr
	case "ipv6addr":
		return TypeIPv6Addr
	case "ipv4prefix":
		return TypeIPv4Prefix
	case "ipv6prefix":
		return TypeIPv6Prefix
	case "ether":
		return TypeEther
	case "ifid":
		return TypeIfid
	case "date":
		return TypeDate
	case "time_delta":
		return TypeTimeDelta
	case "attribute":
		return TypeAttribute
	case "struct":
		return TypeStruct
	case "tlv":
		return TypeTLV
	case "group":
		return TypeGroup
	case "vsa":
		return TypeVSA
	case "union":
		return TypeUnion
	}
	return TypeUnknown
}

// Attr describes a single attribute parsed from the dictionary.
//
// For top-level attributes Code is the option/header code (DHCPv4 options
// 1..254, DHCPv4 BOOTP-header pseudo-attrs 256+, DHCPv6 options 1..65535,
// DHCPv6 header pseudo-attrs 65536+). For attributes inside a vendor block
// Vendor is the enterprise number and Code is the sub-option number.
type Attr struct {
	Name     string
	Code     uint32
	Type     AttrType
	Flags    AttrFlags
	Vendor   uint32 // 0 for non-vendor attrs
	Internal bool   // FLAGS internal — header pseudo-attr, not an option

	// EnumByName / EnumByValue hold the VALUE statements for this attribute.
	EnumByName  map[string]uint64
	EnumByValue map[uint64]string

	// Children: for TLV / struct / vsa parents, dotted children (e.g. 276.1).
	// Maps sub-code -> child Attr.
	Children map[uint32]*Attr
}

// AttrFlags captures the optional flag tail on an ATTRIBUTE line.
type AttrFlags struct {
	Array  bool
	Concat bool
	// Length is the wire-length tag for length-prefixed octets/string arrays
	// (e.g. "length=uint16" used in DHCPv6 user-class / vendor-class entries).
	LengthPrefix int // 0 = no prefix; otherwise 8/16
	// Raw flag string for any unmodeled flags — printed in diagnostics.
	Raw string
}

// Protocol is a parsed dictionary tree rooted at a BEGIN PROTOCOL block
// (DHCPv4 = 2, DHCPv6 = 3 in FreeRADIUS's protocol-number registry).
type Protocol struct {
	Name string
	Code uint32

	byName map[string]*Attr
	byCode map[uint32]*Attr // for top-level (non-vendor) attrs

	// Vendors: enterprise-number -> vendor name; ByVendor[vendor][code] -> attr.
	Vendors   map[uint32]string
	ByVendor  map[uint32]map[uint32]*Attr
	VendorsByName map[string]uint32
}

func newProtocol(name string, code uint32) *Protocol {
	return &Protocol{
		Name:          name,
		Code:          code,
		byName:        make(map[string]*Attr),
		byCode:        make(map[uint32]*Attr),
		Vendors:       make(map[uint32]string),
		ByVendor:      make(map[uint32]map[uint32]*Attr),
		VendorsByName: make(map[string]uint32),
	}
}

// AttrByName resolves an attribute by name within this protocol.
func (p *Protocol) AttrByName(name string) (*Attr, bool) {
	a, ok := p.byName[name]
	return a, ok
}

// AttrByCode resolves a top-level attribute by code.
func (p *Protocol) AttrByCode(code uint32) (*Attr, bool) {
	a, ok := p.byCode[code]
	return a, ok
}

// VendorAttrByCode resolves a vendor sub-option by enterprise + sub-code.
func (p *Protocol) VendorAttrByCode(vendor, code uint32) (*Attr, bool) {
	v, ok := p.ByVendor[vendor]
	if !ok {
		return nil, false
	}
	a, ok := v[code]
	return a, ok
}

// All returns every top-level attribute in deterministic name order. Used by
// debug / diagnostic code.
func (p *Protocol) All() []*Attr {
	out := make([]*Attr, 0, len(p.byName))
	for _, a := range p.byName {
		out = append(out, a)
	}
	return out
}

// addAttr registers a fully-built attribute into the protocol.
func (p *Protocol) addAttr(a *Attr) error {
	if a.Vendor != 0 {
		m := p.ByVendor[a.Vendor]
		if m == nil {
			m = make(map[uint32]*Attr)
			p.ByVendor[a.Vendor] = m
		}
		if existing, ok := m[a.Code]; ok && existing.Name != a.Name {
			return fmt.Errorf("vendor %d: duplicate sub-attr %d (%s vs %s)", a.Vendor, a.Code, existing.Name, a.Name)
		}
		m[a.Code] = a
		p.byName[a.Name] = a
		return nil
	}
	if existing, ok := p.byCode[a.Code]; ok && existing.Name != a.Name && !existing.Internal && !a.Internal {
		return fmt.Errorf("duplicate attr code %d (%s vs %s)", a.Code, existing.Name, a.Name)
	}
	p.byCode[a.Code] = a
	p.byName[a.Name] = a
	return nil
}
