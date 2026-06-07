package attrs

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/ludomikula/dhcpdbg/internal/dict"
)

// ReadList parses the `Attr = value` form (one per line, blank-line-separated
// records, `#` comments) into a slice of Pair lists — one per record.
//
// In addition to plain `Name = value`, the reader supports a dotted form
// that walks a struct/group hierarchy:
//
//	Foo.Bar.Baz = value      — set the Baz MEMBER of the Bar MEMBER of struct Foo
//	Foo.Options.Sub = value  — set Sub as a nested option inside Foo.Options (group)
//	Foo.Options.Sub[1].X = … — second occurrence of Sub in Foo.Options
//
// The walker consults the dictionary at every segment: struct members come
// from Attr.Members, and group sub-options are resolved as separate
// protocol-level attributes that nest under the group.
//
// Errors include the offending line number, the resolved path so far, and
// the failing segment.
func ReadList(r io.Reader, proto *dict.Protocol) ([][]Pair, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var out [][]Pair
	current := newRecordState()
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		raw := scanner.Text()
		line := stripLineComment(raw)
		if line == "" {
			if len(current.pairs) > 0 {
				out = append(out, current.pairs)
				current = newRecordState()
			}
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			return nil, fmt.Errorf("line %d: missing '=' in %q", lineNo, raw)
		}
		path := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		if strings.HasSuffix(path, ":") || strings.HasSuffix(path, "+") {
			path = strings.TrimRight(path, ":+")
			path = strings.TrimSpace(path)
		}
		if err := current.assign(proto, path, val); err != nil {
			return nil, fmt.Errorf("line %d: %v", lineNo, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(current.pairs) > 0 {
		out = append(out, current.pairs)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no packets in input")
	}
	return out, nil
}

// recordState tracks an in-progress record being assembled across many
// dotted-form lines.
type recordState struct {
	pairs []Pair
	// topByName indexes top-level pairs so the second time we see a path
	// rooted at the same name we update the existing struct/group tree
	// rather than starting a new top-level Pair.
	topByName map[string]int
}

func newRecordState() *recordState {
	return &recordState{topByName: make(map[string]int)}
}

// assign walks a dotted path into the existing tree (creating intermediate
// structs and group sub-pairs as needed) and stores val at the leaf.
func (rs *recordState) assign(proto *dict.Protocol, path, val string) error {
	segs, err := splitPath(path)
	if err != nil {
		return err
	}
	if len(segs) == 0 {
		return fmt.Errorf("empty attribute path")
	}

	// Top segment resolves to a protocol-level attribute (or a synthetic
	// MEMBER name from the dictionary — but those only matter inside a
	// struct, never as the first segment).
	rootAttr, ok := proto.AttrByName(segs[0].name)
	if !ok {
		return fmt.Errorf("unknown attribute %q", segs[0].name)
	}

	// Top-level instance key. `V-I-Vendor-Specific[0]` and
	// `V-I-Vendor-Specific` resolve to the same entry; `[1]` and higher
	// create new Pairs so an option can carry multiple PEN segments.
	topKey := segs[0].name
	if segs[0].hasIndex && segs[0].index > 0 {
		topKey = fmt.Sprintf("%s[%d]", segs[0].name, segs[0].index)
	}

	// Find or create the top-level Pair for rootAttr.
	idx, present := rs.topByName[topKey]
	if !present {
		rs.pairs = append(rs.pairs, Pair{Attr: rootAttr, Value: Value{Type: rootAttr.Type}})
		idx = len(rs.pairs) - 1
		rs.topByName[topKey] = idx
	}
	pair := &rs.pairs[idx]

	// Single-segment scalar assignment.
	if len(segs) == 1 {
		v, perr := Parse(rootAttr, val, proto)
		if perr != nil {
			return perr
		}
		// If the attribute is array-typed and we've already seen it, append
		// a fresh Pair so each line becomes its own array element. The
		// encoder aggregates them.
		if present && rootAttr.Flags.Array {
			rs.pairs = append(rs.pairs, Pair{Attr: rootAttr, Value: v})
			rs.topByName[segs[0].name] = len(rs.pairs) - 1
			return nil
		}
		pair.Value = v
		return nil
	}

	// Multi-segment — walk into a struct / group tree.
	return walkAndAssign(proto, rootAttr, &pair.Value, segs[1:], val)
}

// walkAndAssign descends into a struct/group container by name, creating
// intermediate StructValue / Pair nodes as required, and finally writes the
// leaf value parsed against the leaf attribute or member's type.
func walkAndAssign(proto *dict.Protocol, parent *dict.Attr, v *Value, segs []pathSeg, raw string) error {
	if len(segs) == 0 {
		return fmt.Errorf("internal: walkAndAssign called with no segments")
	}
	seg := segs[0]

	switch parent.Type {
	case dict.TypeStruct, dict.TypeUnion:
		m := parent.MemberByName(seg.name)
		// If the segment isn't a direct MEMBER, look it up as a protocol-level
		// attribute. This is how `Client-ID.LLT.<x>` works: LLT is a union
		// variant registered as its own struct ATTRIBUTE inside the BEGIN
		// Client-ID.Value block. We synthesise a member named after the
		// variant and walk into the variant struct's own MEMBERs.
		var variantAttr *dict.Attr
		if m == nil {
			if a, ok := proto.AttrByName(seg.name); ok && (a.Type == dict.TypeStruct || a.Type == dict.TypeUnion) {
				variantAttr = a
				m = &dict.Member{Name: a.Name, Type: a.Type}
			}
		}
		if m == nil {
			return fmt.Errorf("%s: no member %q", parent.Name, seg.name)
		}
		// Ensure the Value type tracks struct.
		if v.Type != dict.TypeStruct && v.Type != dict.TypeUnion {
			v.Type = parent.Type
		}
		mv := v.MemberByName(seg.name)
		if mv == nil {
			v.Members = append(v.Members, MemberValue{Member: m, Value: Value{Type: m.Type}})
			mv = v.MemberByName(seg.name)
		}
		if len(segs) == 1 {
			leaf, err := parseMemberValue(m, raw, proto)
			if err != nil {
				return err
			}
			mv.Value = leaf
			return nil
		}
		// More segments — the member must itself be group, struct, or union.
		switch m.Type {
		case dict.TypeGroup:
			return walkGroupAndAssign(proto, &mv.Value, segs[1:], raw, seg.index)
		case dict.TypeStruct, dict.TypeUnion:
			next := variantAttr
			if next == nil {
				// Try looking up the member name as an attr too (covers the
				// case where the dictionary defines a struct member with the
				// same name as a top-level attr).
				if a, ok := proto.AttrByName(m.Name); ok && len(a.Members) > 0 {
					next = a
				}
			}
			if next == nil {
				return fmt.Errorf("%s.%s: nested struct has no resolvable members", parent.Name, m.Name)
			}
			return walkAndAssign(proto, next, &mv.Value, segs[1:], raw)
		default:
			return fmt.Errorf("%s.%s: not a container (%s)", parent.Name, m.Name, m.Type)
		}
	case dict.TypeGroup:
		// We arrived here directly from a top-level group attribute.
		return walkGroupAndAssign(proto, v, segs, raw, 0)
	case dict.TypeTLV:
		// TLV container — look up the next segment in parent.Children, then
		// either store the leaf value or recurse further.
		return walkTLVAndAssign(proto, parent, v, segs, raw)
	default:
		return fmt.Errorf("%s: cannot descend into a non-struct attribute", parent.Name)
	}
}

// walkTLVAndAssign descends through a TLV container's Children map. The
// container's Value is treated as a group-of-sub-options so the codec can
// emit the children as code(1)+len(1)+value sub-TLVs (DHCPv4 option 82) or
// as a vendor-specific structured payload (FR Decoded-Option-43).
func walkTLVAndAssign(proto *dict.Protocol, parent *dict.Attr, v *Value, segs []pathSeg, raw string) error {
	if len(segs) == 0 {
		return fmt.Errorf("%s: TLV requires a sub-attribute name", parent.Name)
	}
	seg := segs[0]
	child, ok := parent.Children[lookupChildCode(parent, seg.name)]
	if !ok {
		return fmt.Errorf("%s: no sub-attribute %q", parent.Name, seg.name)
	}
	if v.Type != dict.TypeTLV && v.Type != dict.TypeGroup {
		v.Type = dict.TypeTLV
	}
	target := findOrCreateGroupChild(v, child, seg.index)
	if len(segs) == 1 {
		leaf, err := Parse(child, raw, proto)
		if err != nil {
			return err
		}
		target.Value = leaf
		return nil
	}
	return walkAndAssign(proto, child, &target.Value, segs[1:], raw)
}

// lookupChildCode returns the sub-code for a Children entry by name.
// Children is keyed by sub-code; we walk it once per lookup which is fine
// for typical TLV containers (a handful of children).
func lookupChildCode(parent *dict.Attr, name string) uint32 {
	for code, c := range parent.Children {
		if c.Name == name {
			return code
		}
	}
	return 0
}

// walkGroupAndAssign resolves the next segment as a protocol-level
// attribute, then either stores the leaf (single remaining segment, leaf
// type) or recurses (struct/group child).
func walkGroupAndAssign(proto *dict.Protocol, v *Value, segs []pathSeg, raw string, _ int) error {
	if len(segs) == 0 {
		return fmt.Errorf("group requires a sub-attribute name")
	}
	seg := segs[0]
	child, ok := proto.AttrByName(seg.name)
	if !ok {
		return fmt.Errorf("group: unknown sub-attribute %q", seg.name)
	}
	// Locate or create the indexed instance inside v.Group.
	target := findOrCreateGroupChild(v, child, seg.index)

	if len(segs) == 1 {
		leaf, err := Parse(child, raw, proto)
		if err != nil {
			return err
		}
		target.Value = leaf
		return nil
	}
	return walkAndAssign(proto, child, &target.Value, segs[1:], raw)
}

// findOrCreateGroupChild returns a pointer into v.Group for the `index`-th
// pair with Attr == child, creating intermediate empties as needed.
func findOrCreateGroupChild(v *Value, child *dict.Attr, index int) *Pair {
	// Count existing pairs with the same Attr.
	matches := 0
	for i := range v.Group {
		if v.Group[i].Attr == child {
			if matches == index {
				return &v.Group[i]
			}
			matches++
		}
	}
	for matches <= index {
		v.Group = append(v.Group, Pair{Attr: child, Value: Value{Type: child.Type}})
		matches++
	}
	// Return the one at `index`. Walk again now that we've inserted enough.
	matches = 0
	for i := range v.Group {
		if v.Group[i].Attr == child {
			if matches == index {
				return &v.Group[i]
			}
			matches++
		}
	}
	return &v.Group[len(v.Group)-1]
}

// parseMemberValue parses a leaf-level value scoped against the MEMBER's
// type and enum table. Synthesises a dict.Attr so the existing Parse helper
// can carry the member's enum table.
func parseMemberValue(m *dict.Member, raw string, proto *dict.Protocol) (Value, error) {
	syn := &dict.Attr{
		Name:        m.Name,
		Type:        m.Type,
		EnumByName:  m.EnumByName,
		EnumByValue: m.EnumByValue,
	}
	return Parse(syn, raw, proto)
}

// pathSeg is one node in a dotted assignment path. `Foo[2]` -> {"Foo", 2, true}.
type pathSeg struct {
	name     string
	index    int
	hasIndex bool
}

var indexRe = regexp.MustCompile(`^([A-Za-z0-9_.\-]+)\[(\d+)\]$`)

func splitPath(p string) ([]pathSeg, error) {
	parts := strings.Split(p, ".")
	out := make([]pathSeg, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("empty path segment in %q", p)
		}
		if m := indexRe.FindStringSubmatch(part); m != nil {
			n, err := strconv.Atoi(m[2])
			if err != nil {
				return nil, fmt.Errorf("bad index in segment %q", part)
			}
			out = append(out, pathSeg{name: m[1], index: n, hasIndex: true})
			continue
		}
		out = append(out, pathSeg{name: part})
	}
	return out, nil
}

func stripLineComment(s string) string {
	// FreeRADIUS treats '#' as comment only outside of quoted strings.
	inQ := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' && (i == 0 || s[i-1] != '\\') {
			inQ = !inQ
		}
		if c == '#' && !inQ {
			s = s[:i]
			break
		}
	}
	return strings.TrimSpace(s)
}

// WriteList prints a single record to w. Plain pairs round-trip as
// `Name = value`; struct/group pairs expand into one dotted line per leaf
// so the printed output round-trips back through ReadList.
func WriteList(w io.Writer, list []Pair) error {
	for _, p := range list {
		if err := writePair(w, p.Attr.Name, p); err != nil {
			return err
		}
	}
	return nil
}

func writePair(w io.Writer, prefix string, p Pair) error {
	switch p.Value.Type {
	case dict.TypeStruct, dict.TypeUnion:
		// One line per leaf MEMBER.
		for _, mv := range p.Value.Members {
			child := prefix + "." + mv.Member.Name
			if err := writeMember(w, child, mv); err != nil {
				return err
			}
		}
		return nil
	case dict.TypeGroup:
		// Index repeated sub-attrs so re-reading the output stays unambiguous.
		counts := map[string]int{}
		for _, sub := range p.Value.Group {
			n := counts[sub.Attr.Name]
			counts[sub.Attr.Name]++
			label := sub.Attr.Name
			if n > 0 {
				label = fmt.Sprintf("%s[%d]", sub.Attr.Name, n)
			}
			if err := writePair(w, prefix+"."+label, sub); err != nil {
				return err
			}
		}
		return nil
	}
	_, err := fmt.Fprintf(w, "%s = %s\n", prefix, Format(p.Attr, p.Value))
	return err
}

func writeMember(w io.Writer, prefix string, mv MemberValue) error {
	switch mv.Value.Type {
	case dict.TypeStruct, dict.TypeUnion:
		for _, sub := range mv.Value.Members {
			if err := writeMember(w, prefix+"."+sub.Member.Name, sub); err != nil {
				return err
			}
		}
		return nil
	case dict.TypeGroup:
		counts := map[string]int{}
		for _, sub := range mv.Value.Group {
			n := counts[sub.Attr.Name]
			counts[sub.Attr.Name]++
			label := sub.Attr.Name
			if n > 0 {
				label = fmt.Sprintf("%s[%d]", sub.Attr.Name, n)
			}
			if err := writePair(w, prefix+"."+label, sub); err != nil {
				return err
			}
		}
		return nil
	}
	// Synthesise a leaf attr so Format can use the MEMBER's enum table.
	syn := &dict.Attr{
		Name:        mv.Member.Name,
		Type:        mv.Member.Type,
		EnumByName:  mv.Member.EnumByName,
		EnumByValue: mv.Member.EnumByValue,
	}
	_, err := fmt.Fprintf(w, "%s = %s\n", prefix, Format(syn, mv.Value))
	return err
}
