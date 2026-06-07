package dict

import (
	"bufio"
	"embed"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// dictFS / dictRoot are wired up by embed.go's init().
var dictFS embed.FS
var dictRoot string

// LoadDHCPv4 parses the embedded DHCPv4 protocol tree and returns its
// Protocol object.
func LoadDHCPv4() (*Protocol, error) {
	return loadProtocolRoot("dhcpv4/dictionary")
}

// LoadDHCPv6 parses the embedded DHCPv6 protocol tree.
func LoadDHCPv6() (*Protocol, error) {
	return loadProtocolRoot("dhcpv6/dictionary")
}

func loadProtocolRoot(relPath string) (*Protocol, error) {
	p := &parser{
		proto: nil, // set by BEGIN PROTOCOL
	}
	if err := p.parseFile(relPath); err != nil {
		return nil, err
	}
	if p.proto == nil {
		return nil, fmt.Errorf("%s: no BEGIN PROTOCOL block found", relPath)
	}
	return p.proto, nil
}

// parser holds the mutable state for one full dictionary parse: current
// protocol, current vendor stack, current FLAGS scope, current attribute-name
// prefix (for dotted/relative ATTRIBUTE lines), and the namespace stack from
// BEGIN <name>.<member> blocks.
type parser struct {
	proto *Protocol

	vendorStack    []uint32  // BEGIN-VENDOR / END-VENDOR
	nsStack        []*Attr   // BEGIN Foo.Bar / END Foo.Bar — current "struct" context
	flagsInternal  bool      // FLAGS internal (until next FLAGS line or EOF)
	lastAttr       *Attr     // last ATTRIBUTE seen — used by `ATTRIBUTE .Sub` relative form

	// includedOnce avoids cycles if a dictionary $INCLUDEs another that
	// $INCLUDEs back (unlikely but cheap to guard against).
	includedOnce map[string]bool
}

func (p *parser) parseFile(relPath string) error {
	if p.includedOnce == nil {
		p.includedOnce = make(map[string]bool)
	}
	if p.includedOnce[relPath] {
		return nil
	}
	p.includedOnce[relPath] = true

	full := dictRoot + "/" + relPath
	f, err := dictFS.Open(full)
	if err != nil {
		return fmt.Errorf("open %s: %w", relPath, err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	lineNo := 0
	for scanner.Scan() {
		lineNo++
		raw := scanner.Text()
		line := stripComment(raw)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "$INCLUDE":
			if len(fields) < 2 {
				return locErr(relPath, lineNo, "missing $INCLUDE path")
			}
			// Includes are relative to the directory of the including file.
			dir := relPath
			if idx := strings.LastIndex(dir, "/"); idx >= 0 {
				dir = dir[:idx]
			} else {
				dir = ""
			}
			incPath := fields[1]
			if dir != "" {
				incPath = dir + "/" + incPath
			}
			// FLAGS scope is per-file: save and restore around the include
			// so `FLAGS internal` inside dictionary.freeradius.internal does
			// not leak into the next $INCLUDE'd file.
			savedFlags := p.flagsInternal
			savedLast := p.lastAttr
			if err := p.parseFile(incPath); err != nil {
				return err
			}
			p.flagsInternal = savedFlags
			p.lastAttr = savedLast
		case "BEGIN":
			if err := p.handleBegin(fields); err != nil {
				return locErr(relPath, lineNo, err.Error())
			}
		case "END":
			if err := p.handleEnd(fields); err != nil {
				return locErr(relPath, lineNo, err.Error())
			}
		case "FLAGS":
			if len(fields) >= 2 && fields[1] == "internal" {
				p.flagsInternal = true
			} else {
				p.flagsInternal = false
			}
		case "PROTOCOL":
			// Standalone PROTOCOL declarations (number-of-protocols list).
			// Ignored.
		case "VENDOR":
			if err := p.handleVendor(fields); err != nil {
				return locErr(relPath, lineNo, err.Error())
			}
		case "BEGIN-VENDOR":
			if len(fields) < 2 {
				return locErr(relPath, lineNo, "BEGIN-VENDOR needs a name")
			}
			vname := fields[1]
			vn, ok := p.proto.VendorsByName[vname]
			if !ok {
				return locErr(relPath, lineNo, "unknown vendor "+vname)
			}
			p.vendorStack = append(p.vendorStack, vn)
		case "END-VENDOR":
			if len(p.vendorStack) == 0 {
				return locErr(relPath, lineNo, "END-VENDOR with empty stack")
			}
			p.vendorStack = p.vendorStack[:len(p.vendorStack)-1]
		case "ATTRIBUTE":
			if err := p.handleAttribute(fields); err != nil {
				return locErr(relPath, lineNo, err.Error())
			}
		case "MEMBER":
			// MEMBER declarations describe struct internals. For dhcpdbg's
			// purposes we don't reify them — the encoder/decoder treats
			// struct-typed top-level attributes as opaque octets or via
			// hand-coded special cases. We still parse the line so that any
			// trailing VALUE statements inside a BEGIN block are scoped
			// correctly via lastAttr.
			//
			// Format: MEMBER <name> <type> [flags...]
			if len(fields) >= 3 {
				// Create a synthetic Attr for VALUE scoping under nsStack.
				a := &Attr{
					Name: p.qualifiedName(fields[1]),
					Type: ParseType(fields[2]),
				}
				p.lastAttr = a
			}
		case "VALUE":
			if err := p.handleValue(fields); err != nil {
				return locErr(relPath, lineNo, err.Error())
			}
		case "STRUCT":
			// STRUCT statements declare a key-discriminated struct variant.
			// We don't model these for dhcpdbg; skip silently.
		case "ALIAS":
			// ALIAS <new> <existing> — register a name alias.
			if len(fields) >= 3 && p.proto != nil {
				if a, ok := p.proto.byName[fields[2]]; ok {
					p.proto.byName[fields[1]] = a
				}
			}
		default:
			// Unknown directives are tolerated (forward-compat).
		}
	}
	return scanner.Err()
}

// stripComment removes a trailing `# ...` comment respecting bare text only —
// dictionary files don't quote `#` inside values.
func stripComment(s string) string {
	if i := strings.IndexByte(s, '#'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

func (p *parser) handleBegin(fields []string) error {
	if len(fields) < 2 {
		return fmt.Errorf("BEGIN needs argument")
	}
	switch fields[1] {
	case "PROTOCOL":
		if len(fields) < 4 {
			return fmt.Errorf("BEGIN PROTOCOL <name> <num> [...]")
		}
		num, err := strconv.ParseUint(fields[3], 0, 32)
		if err != nil {
			return fmt.Errorf("bad PROTOCOL number %q: %v", fields[3], err)
		}
		p.proto = newProtocol(fields[2], uint32(num))
		return nil
	}
	// BEGIN Foo.Bar — push namespace.
	qual := fields[1]
	// We use the name as a string key — the parser doesn't need to resolve
	// it back to a parent Attr because we ignore struct internals.
	syn := &Attr{Name: qual}
	p.nsStack = append(p.nsStack, syn)
	return nil
}

func (p *parser) handleEnd(fields []string) error {
	if len(fields) < 2 {
		return fmt.Errorf("END needs argument")
	}
	if fields[1] == "PROTOCOL" {
		// END PROTOCOL closes the top-level protocol block — leave p.proto
		// alone (caller still wants it).
		return nil
	}
	if len(p.nsStack) == 0 {
		return fmt.Errorf("END %s with empty namespace stack", fields[1])
	}
	p.nsStack = p.nsStack[:len(p.nsStack)-1]
	return nil
}

func (p *parser) handleVendor(fields []string) error {
	// VENDOR <name> <num> [format=...]
	if len(fields) < 3 {
		return fmt.Errorf("VENDOR needs name and number")
	}
	num, err := strconv.ParseUint(fields[2], 0, 32)
	if err != nil {
		return fmt.Errorf("bad VENDOR number %q", fields[2])
	}
	if p.proto != nil {
		p.proto.Vendors[uint32(num)] = fields[1]
		p.proto.VendorsByName[fields[1]] = uint32(num)
	}
	return nil
}

func (p *parser) handleAttribute(fields []string) error {
	// ATTRIBUTE <name> <code-spec> <type> [flags...]
	if p.proto == nil {
		// Allow pre-PROTOCOL FLAGS/ATTRIBUTE in a dictionary that's not the
		// root — but in our embedded tree this shouldn't happen because we
		// always enter via the protocol-root dictionary file.
		return fmt.Errorf("ATTRIBUTE before BEGIN PROTOCOL")
	}
	if len(fields) < 4 {
		return fmt.Errorf("ATTRIBUTE needs name code type")
	}
	name := fields[1]
	codeSpec := fields[2]
	typeTok := fields[3]
	flagsTok := ""
	if len(fields) > 4 {
		flagsTok = strings.Join(fields[4:], " ")
	}

	code, vendorOverride, isNested, err := parseCodeSpec(codeSpec, p.lastAttr)
	if err != nil {
		return err
	}

	at := ParseType(typeTok)
	if at == TypeUnknown {
		// Treat unknown types as octets so we keep loading the dictionary.
		at = TypeOctets
	}

	a := &Attr{
		Name:     name,
		Code:     code,
		Type:     at,
		Flags:    parseFlags(flagsTok),
		Internal: p.flagsInternal,
	}
	if vendorOverride != 0 {
		a.Vendor = vendorOverride
	} else if len(p.vendorStack) > 0 {
		a.Vendor = p.vendorStack[len(p.vendorStack)-1]
	}

	// Anything inside an active BEGIN <ns>.<member> block is also nested —
	// it's a union-key variant of the parent struct, not a protocol-level
	// option (e.g. HMAC-SHA1-keyed-hash inside Authentication).
	nestedByNs := len(p.nsStack) > 0
	if isNested || nestedByNs {
		// Keep the name lookup so users can still reference these textually
		// if they need to address a sub-attr, but skip the byCode index where
		// the small code would collide with real top-level DHCP options.
		p.proto.byName[a.Name] = a
	} else {
		if err := p.proto.addAttr(a); err != nil {
			return err
		}
	}
	p.lastAttr = a
	return nil
}

// parseCodeSpec handles `<num>`, `<num>.<num>...`, and bare `.<num>` forms.
// Returns (code, vendor-override, nested, err). "Nested" is true for any
// dotted or relative form — the attribute lives inside a parent TLV / struct
// namespace and must NOT be added to the protocol's top-level code map.
//
//   - "53"        -> (53, 0, false, nil)     top-level option
//   - "276.1"     -> (1,  0, true,  nil)     sub-option 1 inside option 276
//   - ".1"        -> (1,  0, true,  nil)     sub-option 1 of lastAttr
func parseCodeSpec(spec string, last *Attr) (uint32, uint32, bool, error) {
	if spec == "" {
		return 0, 0, false, fmt.Errorf("empty code spec")
	}
	if spec[0] == '.' {
		n, err := strconv.ParseUint(spec[1:], 0, 32)
		if err != nil {
			return 0, 0, false, fmt.Errorf("bad relative code %q", spec)
		}
		return uint32(n), 0, true, nil
	}
	if i := strings.LastIndexByte(spec, '.'); i >= 0 {
		n, err := strconv.ParseUint(spec[i+1:], 0, 32)
		if err != nil {
			return 0, 0, false, fmt.Errorf("bad dotted code %q", spec)
		}
		return uint32(n), 0, true, nil
	}
	n, err := strconv.ParseUint(spec, 0, 32)
	if err != nil {
		return 0, 0, false, fmt.Errorf("bad code %q", spec)
	}
	_ = last
	return uint32(n), 0, false, nil
}

func parseFlags(tail string) AttrFlags {
	f := AttrFlags{Raw: tail}
	for _, tok := range strings.Split(tail, ",") {
		tok = strings.TrimSpace(tok)
		switch {
		case tok == "":
			// skip
		case tok == "array":
			f.Array = true
		case tok == "concat":
			f.Concat = true
		case strings.HasPrefix(tok, "length="):
			v := strings.TrimPrefix(tok, "length=")
			// Comma-split already happened on the outer call. The value can
			// itself be uint8/uint16 etc.
			switch v {
			case "uint8":
				f.LengthPrefix = 8
			case "uint16":
				f.LengthPrefix = 16
			}
		}
	}
	return f
}

func (p *parser) handleValue(fields []string) error {
	// VALUE <attr> <name> <num>
	if len(fields) < 4 {
		return fmt.Errorf("VALUE needs attr name value")
	}
	attrName := fields[1]
	enumName := fields[2]
	enumStr := fields[3]

	target, ok := p.proto.byName[attrName]
	if !ok {
		// VALUE may refer to a MEMBER inside a BEGIN block, in which case
		// it's a struct-internal enum we don't model. Skip silently.
		return nil
	}
	if target.EnumByName == nil {
		target.EnumByName = make(map[string]uint64)
		target.EnumByValue = make(map[uint64]string)
	}
	val, err := strconv.ParseUint(enumStr, 0, 64)
	if err != nil {
		return fmt.Errorf("bad VALUE %q for %s", enumStr, attrName)
	}
	target.EnumByName[enumName] = val
	target.EnumByValue[val] = enumName
	return nil
}

func (p *parser) qualifiedName(member string) string {
	if len(p.nsStack) == 0 {
		return member
	}
	return p.nsStack[len(p.nsStack)-1].Name + "." + member
}

func locErr(file string, line int, msg string) error {
	return fmt.Errorf("%s:%d: %s", file, line, msg)
}

// readAllForDebug is a sanity helper used by tests/CLI -xx mode.
func readAllForDebug(f io.Reader) string {
	b, _ := io.ReadAll(f)
	return string(b)
}
