// Package info renders the loaded dictionary tree for human and machine
// consumption. It's the back-end for the `--list-dicts` and `--print-dict`
// CLI flags: the user inspects what attributes / vendors / files
// dhcpdbg has parsed without sending any packets.
//
// Two output formats are supported:
//
//   - text  (default) — tabwriter-aligned columns, grouped into sections
//     (top-level options, internal pseudo-attrs, vendor blocks). Mirrors
//     the dotted input syntax so the LHS of a dump line is exactly what
//     the user types into a request input file.
//   - json — a stable, machine-friendly tree (LoadedFiles, Attributes,
//     Vendors). Designed for `dhcpdbg --print-dict --format=json | jq`.
package info

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/ludomikula/dhcpdbg/internal/dict"
)

// Format selects the rendering form.
type Format int

const (
	// FormatText is the human-readable, tabwriter-aligned default.
	FormatText Format = iota
	// FormatJSON serialises a stable tree designed for shell pipelines.
	FormatJSON
)

// ListDicts writes the table of dictionary files that contributed to proto,
// in load order. The attr-count column is filled by counting each Attr's
// Source against each LoadedFile.Source — files that defined no attributes
// still appear (zero count), so the output reflects what was actually
// opened rather than what was incorporated.
func ListDicts(w io.Writer, proto *dict.Protocol, fmtSel Format) error {
	files := proto.LoadedFiles
	counts := attrCountsBySource(proto)
	if fmtSel == FormatJSON {
		rows := make([]listDictsJSON, 0, len(files))
		for i, f := range files {
			rows = append(rows, listDictsJSON{
				LoadOrder: i + 1,
				Source:    f.Source,
				Path:      f.Path,
				Attrs:     counts[sourceKey(f.Source, f.Path)],
			})
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(struct {
			Protocol string          `json:"protocol"`
			Files    []listDictsJSON `json:"files"`
		}{Protocol: proto.Name, Files: rows})
	}

	fmt.Fprintf(w, "# %s dictionary — %d files\n\n", proto.Name, len(files))
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "LOAD ORDER\tSOURCE\tPATH\tATTRS")
	for i, f := range files {
		fmt.Fprintf(tw, "%d\t%s\t%s\t%d\n", i+1, f.Source, f.Path, counts[sourceKey(f.Source, f.Path)])
	}
	return tw.Flush()
}

// PrintDict writes the friendly dictionary dump. When vendorFilter is empty
// the full tree is rendered (top-level options + internal pseudo-attrs +
// each vendor block). Otherwise only the named vendor blocks are emitted
// — unknown names produce an error that lists what's available.
func PrintDict(w io.Writer, proto *dict.Protocol, vendorFilter []string, fmtSel Format) error {
	if fmtSel == FormatJSON {
		return printDictJSON(w, proto, vendorFilter)
	}
	return printDictText(w, proto, vendorFilter)
}

// ---------------------------------------------------------------- text path

func printDictText(w io.Writer, proto *dict.Protocol, vendorFilter []string) error {
	if len(vendorFilter) > 0 {
		// Validate names up-front so the output isn't half-emitted on a typo.
		for _, name := range vendorFilter {
			if _, ok := proto.VendorsByName[name]; !ok {
				return fmt.Errorf("unknown vendor %q (available: %s)", name, strings.Join(sortedVendorNames(proto), ", "))
			}
		}
		for _, name := range vendorFilter {
			if err := printVendorText(w, proto, name); err != nil {
				return err
			}
		}
		return nil
	}

	totalAttrs := countTopLevelAttrs(proto) + countInternalAttrs(proto) + countVendorAttrs(proto)
	fmt.Fprintf(w, "# %s dictionary — %d attributes, %d vendor blocks, %d files\n\n",
		proto.Name, totalAttrs, len(proto.VendorsByName), len(proto.LoadedFiles))

	fmt.Fprintln(w, "## Top-level options")
	if err := printAttrTableText(w, topLevelAttrs(proto)); err != nil {
		return err
	}

	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "## Internal pseudo-attributes")
	if err := printAttrTableText(w, internalAttrs(proto)); err != nil {
		return err
	}

	if len(proto.VendorsByName) > 0 {
		fmt.Fprintln(w, "")
		fmt.Fprintln(w, "## Vendors")
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tPEN\tATTRS\tSOURCE")
		for _, name := range sortedVendorNames(proto) {
			pen := proto.VendorsByName[name]
			n := 0
			if m, ok := proto.ByVendor[pen]; ok {
				n = len(m)
			}
			fmt.Fprintf(tw, "%s\t%d\t%d\t%s\n", name, pen, n, shortSource(proto.VendorSources[name]))
		}
		if err := tw.Flush(); err != nil {
			return err
		}
		for _, name := range sortedVendorNames(proto) {
			fmt.Fprintln(w, "")
			if err := printVendorText(w, proto, name); err != nil {
				return err
			}
		}
	}
	return nil
}

// printAttrTableText prints a tabwriter-aligned CODE/TYPE/NAME/SOURCE table
// for the given attribute list, then — for any attribute that carries
// extras (enum values, struct members, TLV children) — a per-attribute
// "Details" block. Keeping the table tight and the extras separate keeps
// long output scrollable; the table is the index, the detail blocks are
// the reference.
func printAttrTableText(w io.Writer, attrs []*dict.Attr) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "CODE\tTYPE\tNAME\tSOURCE")
	for _, a := range attrs {
		fmt.Fprintf(tw, "%d\t%s\t%s%s\t%s\n",
			a.Code, a.Type.String(), a.Name, flagsSuffix(a), shortSourceAttr(a))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	// Per-attribute detail blocks.
	for _, a := range attrs {
		if !hasExtras(a) {
			continue
		}
		fmt.Fprintf(w, "\n### %s (%d)\n", a.Name, a.Code)
		writeAttrExtras(w, a, "    ")
	}
	return nil
}

// hasExtras reports whether the attribute has any follow-up data worth
// rendering in a Details block (enum values, struct members, TLV children).
func hasExtras(a *dict.Attr) bool {
	return a != nil && (len(a.EnumByName) > 0 || len(a.Members) > 0 || len(a.Children) > 0)
}

// writeAttrExtras renders the per-attribute follow-up lines:
//   - VALUE table (one line per enum entry)
//   - MEMBER rows (struct/union members)
//   - SUB rows (TLV children, recursive — each child gets its own
//     indented block when it has further extras of its own)
//
// indent is the leading whitespace; recursion deepens it by four spaces
// so nested containers (Decoded-Option-43 → Broadband-Forum → ACS-URL)
// are visually distinct.
func writeAttrExtras(w io.Writer, a *dict.Attr, indent string) {
	if a == nil {
		return
	}
	// Per-block tabwriter so VALUE / MEMBER / SUB columns line up.
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if len(a.EnumByName) > 0 {
		names := make([]string, 0, len(a.EnumByName))
		for n := range a.EnumByName {
			names = append(names, n)
		}
		sort.Slice(names, func(i, j int) bool {
			return a.EnumByName[names[i]] < a.EnumByName[names[j]]
		})
		for _, n := range names {
			fmt.Fprintf(tw, "%sVALUE\t%s\t= %d\n", indent, n, a.EnumByName[n])
		}
	}
	for _, m := range a.Members {
		fmt.Fprintf(tw, "%sMEMBER\t%s\t%s%s\n", indent, m.Name, m.Type.String(), memberFlagsSuffix(m))
	}
	if len(a.Children) > 0 {
		codes := make([]uint32, 0, len(a.Children))
		for c := range a.Children {
			codes = append(codes, c)
		}
		sort.Slice(codes, func(i, j int) bool { return codes[i] < codes[j] })
		for _, c := range codes {
			child := a.Children[c]
			fmt.Fprintf(tw, "%sSUB\t%d\t%s\t%s%s\t%s\n",
				indent, c, child.Type.String(), child.Name, flagsSuffix(child), shortSourceAttr(child))
		}
	}
	_ = tw.Flush()
	// Recurse into children that have their own extras. We emit the child
	// row inside the tabwriter above; the recursion only adds further
	// indented detail when the child itself has VALUEs / MEMBERs / SUBs.
	if len(a.Children) > 0 {
		codes := make([]uint32, 0, len(a.Children))
		for c := range a.Children {
			codes = append(codes, c)
		}
		sort.Slice(codes, func(i, j int) bool { return codes[i] < codes[j] })
		for _, c := range codes {
			child := a.Children[c]
			if !hasExtras(child) {
				continue
			}
			fmt.Fprintf(w, "%s    └─ %s (%d):\n", indent, child.Name, child.Code)
			writeAttrExtras(w, child, indent+"        ")
		}
	}
}

// printVendorText emits a `Vendor: <Name> (PEN N)` header followed by the
// CODE/TYPE/NAME/SOURCE table for that vendor's attributes (and their
// sub-trees).
func printVendorText(w io.Writer, proto *dict.Protocol, name string) error {
	pen := proto.VendorsByName[name]
	attrs := vendorAttrs(proto, pen)
	fmt.Fprintf(w, "## Vendor: %s (PEN %d) — %d attributes  [%s]\n",
		name, pen, len(attrs), shortSource(proto.VendorSources[name]))
	return printAttrTableText(w, attrs)
}

// ---------------------------------------------------------------- JSON path

type listDictsJSON struct {
	LoadOrder int    `json:"load_order"`
	Source    string `json:"source"`
	Path      string `json:"path"`
	Attrs     int    `json:"attrs"`
}

type attrJSON struct {
	Code       uint32              `json:"code"`
	Name       string              `json:"name"`
	Type       string              `json:"type"`
	Vendor     uint32              `json:"vendor,omitempty"`
	Internal   bool                `json:"internal,omitempty"`
	Source     string              `json:"source,omitempty"`
	SourceFile string              `json:"source_file,omitempty"`
	Flags      *attrFlagsJSON      `json:"flags,omitempty"`
	Enum       map[string]uint64   `json:"enum,omitempty"`
	Members    []memberJSON        `json:"members,omitempty"`
	Children   map[string]attrJSON `json:"children,omitempty"`
}

type attrFlagsJSON struct {
	Array  bool `json:"array,omitempty"`
	Concat bool `json:"concat,omitempty"`
	Length int  `json:"length_prefix,omitempty"`
}

type memberJSON struct {
	Name         string `json:"name"`
	Type         string `json:"type"`
	Array        bool   `json:"array,omitempty"`
	Key          bool   `json:"key,omitempty"`
	KeyRef       string `json:"key_ref,omitempty"`
	LengthPrefix int    `json:"length_prefix,omitempty"`
	FixedSize    int    `json:"fixed_size,omitempty"`
}

type vendorJSON struct {
	Name       string     `json:"name"`
	PEN        uint32     `json:"pen"`
	Source     string     `json:"source,omitempty"`
	SourceFile string     `json:"source_file,omitempty"`
	Attributes []attrJSON `json:"attributes,omitempty"`
}

type dictJSON struct {
	Protocol           string       `json:"protocol"`
	ProtocolCode       uint32       `json:"protocol_code"`
	TopLevelAttributes []attrJSON   `json:"top_level_attributes,omitempty"`
	InternalAttributes []attrJSON   `json:"internal_attributes,omitempty"`
	Vendors            []vendorJSON `json:"vendors,omitempty"`
}

func printDictJSON(w io.Writer, proto *dict.Protocol, vendorFilter []string) error {
	if len(vendorFilter) > 0 {
		for _, name := range vendorFilter {
			if _, ok := proto.VendorsByName[name]; !ok {
				return fmt.Errorf("unknown vendor %q (available: %s)", name, strings.Join(sortedVendorNames(proto), ", "))
			}
		}
	}

	out := dictJSON{Protocol: proto.Name, ProtocolCode: proto.Code}
	if len(vendorFilter) == 0 {
		out.TopLevelAttributes = attrsToJSON(topLevelAttrs(proto))
		out.InternalAttributes = attrsToJSON(internalAttrs(proto))
	}
	vendorNames := vendorFilter
	if len(vendorNames) == 0 {
		vendorNames = sortedVendorNames(proto)
	}
	for _, name := range vendorNames {
		pen := proto.VendorsByName[name]
		src, srcFile := splitVendorSource(proto.VendorSources[name])
		out.Vendors = append(out.Vendors, vendorJSON{
			Name:       name,
			PEN:        pen,
			Source:     src,
			SourceFile: srcFile,
			Attributes: attrsToJSON(vendorAttrs(proto, pen)),
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func attrsToJSON(attrs []*dict.Attr) []attrJSON {
	out := make([]attrJSON, 0, len(attrs))
	for _, a := range attrs {
		out = append(out, attrToJSON(a))
	}
	return out
}

func attrToJSON(a *dict.Attr) attrJSON {
	j := attrJSON{
		Code:       a.Code,
		Name:       a.Name,
		Type:       a.Type.String(),
		Vendor:     a.Vendor,
		Internal:   a.Internal,
		Source:     a.Source,
		SourceFile: a.SourceFile,
	}
	if a.Flags.Array || a.Flags.Concat || a.Flags.LengthPrefix != 0 {
		j.Flags = &attrFlagsJSON{Array: a.Flags.Array, Concat: a.Flags.Concat, Length: a.Flags.LengthPrefix}
	}
	if len(a.EnumByName) > 0 {
		j.Enum = make(map[string]uint64, len(a.EnumByName))
		for k, v := range a.EnumByName {
			j.Enum[k] = v
		}
	}
	for _, m := range a.Members {
		j.Members = append(j.Members, memberJSON{
			Name:         m.Name,
			Type:         m.Type.String(),
			Array:        m.Array,
			Key:          m.IsKey,
			KeyRef:       m.KeyRef,
			LengthPrefix: m.LengthPrefix,
			FixedSize:    m.FixedSize,
		})
	}
	if len(a.Children) > 0 {
		j.Children = make(map[string]attrJSON, len(a.Children))
		for _, child := range a.Children {
			j.Children[child.Name] = attrToJSON(child)
		}
	}
	return j
}

// ------------------------------------------------------------- helpers / sorting

// topLevelAttrs returns every non-internal, non-vendor attribute sorted by
// code. Container types (TLV/struct/group) keep their full sub-tree which
// the printers render recursively.
func topLevelAttrs(proto *dict.Protocol) []*dict.Attr {
	out := make([]*dict.Attr, 0, 128)
	for _, a := range allAttrs(proto) {
		if a.Internal || a.Vendor != 0 {
			continue
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Code < out[j].Code })
	return out
}

// internalAttrs returns every attribute carrying the `internal` flag — the
// BOOTP-header pseudo-attrs plus FR's helper containers (Decoded-Option-43,
// Packet-Type, ...).
func internalAttrs(proto *dict.Protocol) []*dict.Attr {
	out := make([]*dict.Attr, 0, 32)
	for _, a := range allAttrs(proto) {
		if !a.Internal {
			continue
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Code < out[j].Code })
	return out
}

// vendorAttrs returns the attrs under the given enterprise number, sorted
// by sub-code.
func vendorAttrs(proto *dict.Protocol, pen uint32) []*dict.Attr {
	m := proto.ByVendor[pen]
	if len(m) == 0 {
		return nil
	}
	out := make([]*dict.Attr, 0, len(m))
	for _, a := range m {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Code < out[j].Code })
	return out
}

// allAttrs walks the Protocol's byName map. We re-derive it here rather
// than expose byName on the public Protocol surface — keeps the dict
// package's internal map private. The map happens to have one entry per
// attribute regardless of vendor / nesting depth, which is what we need.
func allAttrs(proto *dict.Protocol) []*dict.Attr {
	// Walk through every code in byCode (top-level + internal), then every
	// vendor map, then collect children recursively. Dedup by pointer.
	seen := make(map[*dict.Attr]bool)
	var out []*dict.Attr
	visit := func(a *dict.Attr) {
		if a == nil || seen[a] {
			return
		}
		seen[a] = true
		out = append(out, a)
	}
	// Top-level (and internal) attributes by code.
	for code := uint32(0); code < 1<<20; code++ {
		if a, ok := proto.AttrByCode(code); ok {
			visit(a)
		}
	}
	// Vendor blocks.
	for _, m := range proto.ByVendor {
		for _, a := range m {
			visit(a)
		}
	}
	return out
}

func countTopLevelAttrs(proto *dict.Protocol) int { return len(topLevelAttrs(proto)) }
func countInternalAttrs(proto *dict.Protocol) int { return len(internalAttrs(proto)) }
func countVendorAttrs(proto *dict.Protocol) int {
	n := 0
	for _, m := range proto.ByVendor {
		n += len(m)
	}
	return n
}

// sortedVendorNames returns the protocol's VendorsByName keys alphabetised.
func sortedVendorNames(proto *dict.Protocol) []string {
	out := make([]string, 0, len(proto.VendorsByName))
	for name := range proto.VendorsByName {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// attrCountsBySource counts attributes per (source, file) pair, keyed by
// the same composite used by sourceKey() so ListDicts can look up counts
// row by row. Attribution is exact: each attr is stamped with the file it
// came from (Attr.SourceFile) at parse time.
func attrCountsBySource(proto *dict.Protocol) map[string]int {
	out := make(map[string]int)
	for _, f := range proto.LoadedFiles {
		out[sourceKey(f.Source, f.Path)] = 0
	}
	for _, a := range allAttrs(proto) {
		out[sourceKey(a.Source, a.SourceFile)]++
	}
	return out
}

func sourceKey(source, path string) string { return source + "::" + path }

// shortSource renders a short source label suitable for a SOURCE column.
// It accepts either a bare source name (`embedded`, `custom:/dir`) or a
// composite `source::file` label (used by VendorSources) and reduces it to
// `<filename>` for embedded or `custom:<basename>` for custom. Empty
// input returns empty.
func shortSource(s string) string {
	if s == "" {
		return ""
	}
	// VendorSources stores `<source>::<file>`. Split if present so we can
	// produce the same tail as shortSourceAttr.
	source, file := s, ""
	if i := strings.Index(s, "::"); i >= 0 {
		source, file = s[:i], s[i+2:]
	}
	if strings.HasPrefix(source, "custom:") {
		base := file
		if base == "" {
			base = source[len("custom:"):]
		}
		if i := strings.LastIndex(base, "/"); i >= 0 {
			base = base[i+1:]
		}
		return "custom:" + base
	}
	if file != "" {
		return embeddedTail(file)
	}
	return source
}

// shortSourceAttr is shortSource but file-aware: for embedded attrs it
// returns the file's short tail (`rfc2131`, `freeradius.internal`,
// `adsl_forum`) extracted from Attr.SourceFile. For custom sources it
// returns `custom:<basename of file>` so the user can tell which custom
// file contributed an override.
func shortSourceAttr(a *dict.Attr) string {
	if a == nil {
		return ""
	}
	if strings.HasPrefix(a.Source, "custom:") {
		base := a.SourceFile
		if base == "" {
			return shortSource(a.Source)
		}
		if i := strings.LastIndex(base, "/"); i >= 0 {
			base = base[i+1:]
		}
		return "custom:" + base
	}
	// Embedded — keep the dictionary's identifying tail.
	return embeddedTail(a.SourceFile)
}

// splitVendorSource splits the composite `<source>::<file>` label stored
// in Protocol.VendorSources into its two halves. If the input has no
// "::" separator we treat it as a bare source name.
func splitVendorSource(s string) (source, file string) {
	if i := strings.Index(s, "::"); i >= 0 {
		return s[:i], s[i+2:]
	}
	return s, ""
}

// embeddedTail collapses `dhcpv4/dictionary.rfc2131` → `rfc2131`,
// `dhcpv4/dictionary.freeradius.internal` → `freeradius.internal`. Falls
// back to the input unchanged when it doesn't match the pattern.
func embeddedTail(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		p = p[i+1:]
	}
	const prefix = "dictionary."
	if strings.HasPrefix(p, prefix) {
		return p[len(prefix):]
	}
	if p == "dictionary" {
		return "root"
	}
	return p
}

// flagsSuffix renders the dictionary's ATTRIBUTE flag tail in the same
// notation used in the source ("array", "length=uint16"). Empty when
// no flags are set.
func flagsSuffix(a *dict.Attr) string {
	parts := []string{}
	if a.Flags.Array {
		parts = append(parts, "array")
	}
	if a.Flags.Concat {
		parts = append(parts, "concat")
	}
	if a.Flags.LengthPrefix > 0 {
		parts = append(parts, fmt.Sprintf("length=uint%d", a.Flags.LengthPrefix))
	}
	if len(parts) == 0 {
		return ""
	}
	return " [" + strings.Join(parts, ",") + "]"
}

func memberFlagsSuffix(m *dict.Member) string {
	parts := []string{}
	if m.Array {
		parts = append(parts, "array")
	}
	if m.IsKey {
		parts = append(parts, "key")
	}
	if m.KeyRef != "" {
		parts = append(parts, "key="+m.KeyRef)
	}
	if m.LengthPrefix > 0 {
		parts = append(parts, fmt.Sprintf("length=uint%d", m.LengthPrefix))
	}
	if m.FixedSize > 0 {
		parts = append(parts, fmt.Sprintf("[%d]", m.FixedSize))
	}
	if len(parts) == 0 {
		return ""
	}
	return " [" + strings.Join(parts, ",") + "]"
}
