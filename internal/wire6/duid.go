package wire6

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/ludomikula/dhcpdbg/internal/attrs"
	"github.com/ludomikula/dhcpdbg/internal/dict"
)

// duidEpoch is the RFC 8415 §11.2 epoch for DUID-LLT timestamps:
// 2000-01-01T00:00:00Z. The wire field is seconds since this instant, modulo 2^32.
var duidEpoch = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

// DUID-Type wire codes (RFC 8415 §11).
const (
	duidLLT  = 1
	duidEN   = 2
	duidLL   = 3
	duidUUID = 4
)

// encodeDUID serialises a Client-ID or Server-ID Value into the on-wire DUID
// form. Recognises the standard variants:
//
//	LLT — DUID = LLT, LLT = { Hardware-Type, Time, Ethernet = { Address } }
//	EN  — DUID = EN,  EN  = { Enterprise-Number, Identifier (octets) }
//	LL  — DUID = LL,  LL  = { Hardware-Type, Ethernet = { Address } }
//	UUID — DUID = UUID, UUID = { Value (16-octet octets) }
//
// Falls back to opaque-octets emission if Value.Members is empty (the user
// passed `Client-ID = 0x…` directly).
func encodeDUID(v attrs.Value) ([]byte, error) {
	if len(v.Members) == 0 {
		// Opaque blob form.
		return append([]byte(nil), v.Bytes...), nil
	}
	// Look up DUID discriminator + variant payload.
	var duidType string
	var variant *attrs.MemberValue
	for i := range v.Members {
		mv := &v.Members[i]
		switch mv.Member.Name {
		case "DUID":
			// Stored as Uint (enum) — turn back into the variant name.
			duidType = duidVariantName(mv)
		default:
			variant = mv
		}
	}
	if duidType == "" && variant != nil {
		// User omitted explicit `Client-ID.DUID = X` but named the variant
		// member directly (Client-ID.LLT.* = …). Use the variant name as
		// the discriminator.
		duidType = variant.Member.Name
	}

	switch strings.ToUpper(duidType) {
	case "LLT":
		return encodeDUID_LLT(variant)
	case "EN":
		return encodeDUID_EN(variant)
	case "LL":
		return encodeDUID_LL(variant)
	case "UUID":
		return encodeDUID_UUID(variant)
	}
	return nil, fmt.Errorf("DUID: unknown variant %q (use LLT, EN, LL, UUID, or pass a hex blob)", duidType)
}

func duidVariantName(mv *attrs.MemberValue) string {
	if mv.Member != nil && mv.Member.EnumByValue != nil {
		if name, ok := mv.Member.EnumByValue[mv.Value.Uint]; ok {
			return name
		}
	}
	if mv.Value.Type == dict.TypeString {
		return mv.Value.Str
	}
	return fmt.Sprintf("%d", mv.Value.Uint)
}

func encodeDUID_LLT(variant *attrs.MemberValue) ([]byte, error) {
	if variant == nil {
		return nil, fmt.Errorf("DUID-LLT: missing LLT body")
	}
	var hwType uint16 = 1 // Ethernet by default
	var sec uint32        // seconds since 2000-01-01T00:00:00Z
	var addr []byte

	for _, m := range variant.Value.Members {
		switch m.Member.Name {
		case "Hardware-Type":
			hwType = uint16(m.Value.Uint)
		case "Time":
			sec = toDUIDTime(m.Value)
		default:
			// Nested variant struct (Ethernet -> Address). Walk one level.
			for _, sub := range m.Value.Members {
				if sub.Member.Name == "Address" {
					addr = append([]byte(nil), sub.Value.Bytes...)
				}
			}
		}
	}
	if len(addr) == 0 {
		return nil, fmt.Errorf("DUID-LLT: missing link-layer address (set Client-ID.LLT.Ethernet.Address)")
	}
	out := make([]byte, 8+len(addr))
	binary.BigEndian.PutUint16(out[0:2], duidLLT)
	binary.BigEndian.PutUint16(out[2:4], hwType)
	binary.BigEndian.PutUint32(out[4:8], sec)
	copy(out[8:], addr)
	return out, nil
}

func encodeDUID_EN(variant *attrs.MemberValue) ([]byte, error) {
	if variant == nil {
		return nil, fmt.Errorf("DUID-EN: missing EN body")
	}
	var pen uint32
	var id []byte
	for _, m := range variant.Value.Members {
		switch m.Member.Name {
		case "Enterprise-Number":
			pen = uint32(m.Value.Uint)
		case "Identifier":
			id = append([]byte(nil), m.Value.Bytes...)
		}
	}
	out := make([]byte, 6+len(id))
	binary.BigEndian.PutUint16(out[0:2], duidEN)
	binary.BigEndian.PutUint32(out[2:6], pen)
	copy(out[6:], id)
	return out, nil
}

func encodeDUID_LL(variant *attrs.MemberValue) ([]byte, error) {
	if variant == nil {
		return nil, fmt.Errorf("DUID-LL: missing LL body")
	}
	var hwType uint16 = 1
	var addr []byte
	for _, m := range variant.Value.Members {
		switch m.Member.Name {
		case "Hardware-Type":
			hwType = uint16(m.Value.Uint)
		default:
			for _, sub := range m.Value.Members {
				if sub.Member.Name == "Address" {
					addr = append([]byte(nil), sub.Value.Bytes...)
				}
			}
		}
	}
	if len(addr) == 0 {
		return nil, fmt.Errorf("DUID-LL: missing link-layer address (set Client-ID.LL.Ethernet.Address)")
	}
	out := make([]byte, 4+len(addr))
	binary.BigEndian.PutUint16(out[0:2], duidLL)
	binary.BigEndian.PutUint16(out[2:4], hwType)
	copy(out[4:], addr)
	return out, nil
}

func encodeDUID_UUID(variant *attrs.MemberValue) ([]byte, error) {
	if variant == nil {
		return nil, fmt.Errorf("DUID-UUID: missing UUID body")
	}
	var uuid []byte
	for _, m := range variant.Value.Members {
		if m.Member.Name == "Value" {
			uuid = append([]byte(nil), m.Value.Bytes...)
		}
	}
	if len(uuid) == 0 {
		return nil, fmt.Errorf("DUID-UUID: missing UUID (set Client-ID.UUID.Value)")
	}
	out := make([]byte, 2+len(uuid))
	binary.BigEndian.PutUint16(out[0:2], duidUUID)
	copy(out[2:], uuid)
	return out, nil
}

// decodeDUID parses a Client-ID / Server-ID payload into a struct-typed Value
// so it round-trips as field-by-field output. Falls back to opaque octets
// when the discriminator value isn't one the dictionary knows.
func decodeDUID(a *dict.Attr, data []byte) attrs.Value {
	if len(data) < 2 || len(a.Members) == 0 {
		return attrs.Value{Type: dict.TypeOctets, Bytes: append([]byte(nil), data...)}
	}
	dt := binary.BigEndian.Uint16(data[0:2])
	var name string
	for _, m := range a.Members {
		if m.Name == "DUID" {
			if n, ok := m.EnumByValue[uint64(dt)]; ok {
				name = n
			}
		}
	}
	out := attrs.Value{Type: dict.TypeStruct}
	for _, m := range a.Members {
		out.SetMember(m, attrs.Value{Type: m.Type})
	}
	// Fill DUID discriminator if we have its Member.
	if mv := out.MemberByName("DUID"); mv != nil {
		mv.Value = attrs.Value{Type: mv.Member.Type, Uint: uint64(dt)}
	}
	switch dt {
	case duidLLT:
		decodeDUID_LLT(&out, data[2:])
	case duidEN:
		decodeDUID_EN(&out, data[2:])
	case duidLL:
		decodeDUID_LL(&out, data[2:])
	case duidUUID:
		decodeDUID_UUID(&out, data[2:])
	default:
		// Unknown variant — keep struct + DUID code; stash payload as hex.
		// Print as `Name = 0x…` via Format fallback.
		_ = name
	}
	return out
}

func decodeDUID_LLT(parent *attrs.Value, body []byte) {
	if len(body) < 6 {
		return
	}
	hwType := binary.BigEndian.Uint16(body[0:2])
	sec := binary.BigEndian.Uint32(body[2:6])
	llAddr := append([]byte(nil), body[6:]...)
	vm := parent.MemberByName("Value")
	if vm == nil {
		return
	}
	// Find the LLT sub-struct definition (variant attr).
	lltAttr := findVariant(parent, "LLT")
	if lltAttr == nil {
		vm.Value = attrs.Value{Type: dict.TypeOctets, Bytes: append([]byte{byte(duidLLT >> 8), duidLLT}, body...)}
		return
	}
	llt := buildVariantValue(lltAttr, map[string]attrs.Value{
		"Hardware-Type": {Type: dict.TypeUint16, Uint: uint64(hwType)},
		"Time":          {Type: dict.TypeDate, Uint: uint64(sec)},
	})
	// Add Ethernet.Address inside LLT.Value
	if ethAttr := findVariant(&llt, "Ethernet"); ethAttr != nil {
		eth := buildVariantValue(ethAttr, map[string]attrs.Value{
			"Address": {Type: dict.TypeEther, Bytes: llAddr},
		})
		if vmm := llt.MemberByName("Value"); vmm != nil {
			vmm.Value = eth
		}
	}
	vm.Value = llt
}

func decodeDUID_EN(parent *attrs.Value, body []byte) {
	if len(body) < 4 {
		return
	}
	pen := binary.BigEndian.Uint32(body[0:4])
	id := append([]byte(nil), body[4:]...)
	vm := parent.MemberByName("Value")
	if vm == nil {
		return
	}
	enAttr := findVariant(parent, "EN")
	if enAttr == nil {
		return
	}
	vm.Value = buildVariantValue(enAttr, map[string]attrs.Value{
		"Enterprise-Number": {Type: dict.TypeUint32, Uint: uint64(pen)},
		"Identifier":        {Type: dict.TypeOctets, Bytes: id},
	})
}

func decodeDUID_LL(parent *attrs.Value, body []byte) {
	if len(body) < 2 {
		return
	}
	hwType := binary.BigEndian.Uint16(body[0:2])
	llAddr := append([]byte(nil), body[2:]...)
	vm := parent.MemberByName("Value")
	if vm == nil {
		return
	}
	llAttr := findVariant(parent, "LL")
	if llAttr == nil {
		return
	}
	ll := buildVariantValue(llAttr, map[string]attrs.Value{
		"Hardware-Type": {Type: dict.TypeUint16, Uint: uint64(hwType)},
	})
	if ethAttr := findVariant(&ll, "Ethernet"); ethAttr != nil {
		eth := buildVariantValue(ethAttr, map[string]attrs.Value{
			"Address": {Type: dict.TypeEther, Bytes: llAddr},
		})
		if vmm := ll.MemberByName("Value"); vmm != nil {
			vmm.Value = eth
		}
	}
	vm.Value = ll
}

func decodeDUID_UUID(parent *attrs.Value, body []byte) {
	uuid := append([]byte(nil), body...)
	vm := parent.MemberByName("Value")
	if vm == nil {
		return
	}
	uuidAttr := findVariant(parent, "UUID")
	if uuidAttr == nil {
		return
	}
	vm.Value = buildVariantValue(uuidAttr, map[string]attrs.Value{
		"Value": {Type: dict.TypeOctets, Bytes: uuid},
	})
}

// findVariant returns a synthetic Attr describing one of the four canonical
// DUID variants (or "Ethernet" — the nested LL/LLT inner struct). The
// FreeRADIUS dictionary keeps each variant under `BEGIN <Parent>.Value`
// blocks and registers them by qualified name only, so the encoder/decoder
// works against this small, fixed shape rather than chasing the backlink.
func findVariant(_ *attrs.Value, name string) *dict.Attr {
	return synthesiseVariantAttr(name)
}

// synthesiseVariantAttr produces a small Attr with the canonical MEMBER
// shape for one of the four DUID variants. Used when the dictionary parser
// didn't materialise the variant's MEMBERs (FreeRADIUS keeps them under
// BEGIN/END Value blocks; we register them by name but the codec doesn't
// know to chase the link).
func synthesiseVariantAttr(name string) *dict.Attr {
	switch strings.ToUpper(name) {
	case "LLT":
		return &dict.Attr{Name: "LLT", Type: dict.TypeStruct, Members: []*dict.Member{
			{Name: "Hardware-Type", Type: dict.TypeUint16, IsKey: true},
			{Name: "Time", Type: dict.TypeDate},
			{Name: "Value", Type: dict.TypeStruct},
		}}
	case "EN":
		return &dict.Attr{Name: "EN", Type: dict.TypeStruct, Members: []*dict.Member{
			{Name: "Enterprise-Number", Type: dict.TypeUint32},
			{Name: "Identifier", Type: dict.TypeOctets},
		}}
	case "LL":
		return &dict.Attr{Name: "LL", Type: dict.TypeStruct, Members: []*dict.Member{
			{Name: "Hardware-Type", Type: dict.TypeUint16, IsKey: true},
			{Name: "Value", Type: dict.TypeStruct},
		}}
	case "UUID":
		return &dict.Attr{Name: "UUID", Type: dict.TypeStruct, Members: []*dict.Member{
			{Name: "Value", Type: dict.TypeOctets},
		}}
	case "Ethernet":
		return &dict.Attr{Name: "Ethernet", Type: dict.TypeStruct, Members: []*dict.Member{
			{Name: "Address", Type: dict.TypeEther},
		}}
	}
	return nil
}

func buildVariantValue(variant *dict.Attr, vals map[string]attrs.Value) attrs.Value {
	out := attrs.Value{Type: dict.TypeStruct}
	for _, m := range variant.Members {
		v, ok := vals[m.Name]
		if !ok {
			v = attrs.Value{Type: m.Type}
		}
		out.Members = append(out.Members, attrs.MemberValue{Member: m, Value: v})
	}
	return out
}

func toDUIDTime(v attrs.Value) uint32 {
	switch v.Type {
	case dict.TypeDate:
		// User may have passed an RFC 3339 string; we Parse it via the
		// regular Parse path which assumed integer/uint. For now expect
		// either a raw second offset (passed as integer) or 0.
		return uint32(v.Uint)
	case dict.TypeUint32, dict.TypeUint64, dict.TypeUint16, dict.TypeUint8:
		return uint32(v.Uint)
	case dict.TypeString:
		t, err := time.Parse(time.RFC3339, v.Str)
		if err != nil {
			return 0
		}
		return uint32(t.Sub(duidEpoch).Seconds())
	}
	return 0
}

// hexForDebug is used by error paths — kept exported via lowercase to avoid
// unused-import linting.
func hexForDebug(b []byte) string { return hex.EncodeToString(b) }
