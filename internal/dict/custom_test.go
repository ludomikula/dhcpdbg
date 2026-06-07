package dict

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFile is a small helper that materialises a temp dictionary file.
func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	full := filepath.Join(dir, name)
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile %s: %v", full, err)
	}
	return full
}

// TestCustomVendorAdds checks that a custom dictionary file can introduce a
// vendor and its sub-attributes on top of the embedded tree.
func TestCustomVendorAdds(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "dictionary.acme", `
VENDOR Acme-Networks 99999
BEGIN-VENDOR Acme-Networks
ATTRIBUTE Custom-Option 1 string
ATTRIBUTE Auth-Token    2 octets
END-VENDOR Acme-Networks
`)
	proto, err := LoadDHCPv4(WithCustomDicts(filepath.Join(dir, "dictionary.acme")))
	if err != nil {
		t.Fatalf("LoadDHCPv4: %v", err)
	}
	if got, ok := proto.VendorsByName["Acme-Networks"]; !ok || got != 99999 {
		t.Fatalf("Acme-Networks vendor not registered: got=%d ok=%v", got, ok)
	}
	a, ok := proto.VendorAttrByCode(99999, 1)
	if !ok {
		t.Fatal("Acme-Networks sub-attribute 1 (Custom-Option) not registered")
	}
	if a.Name != "Custom-Option" || a.Type != TypeString {
		t.Fatalf("unexpected sub-attr: name=%s type=%s", a.Name, a.Type)
	}
	// The embedded standard options must still be present.
	if _, ok := proto.AttrByName("Subnet-Mask"); !ok {
		t.Fatal("embedded Subnet-Mask missing after custom load")
	}
}

// TestCustomValueOverrideWins confirms that a custom dictionary redefining
// a VALUE enum updates the lookup.
func TestCustomValueOverrideWins(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "dictionary.local", `
# Override the well-known Message-Type Discover code to 99 for local testing.
VALUE Message-Type Discover 99
`)
	proto, err := LoadDHCPv4(WithCustomDicts(filepath.Join(dir, "dictionary.local")))
	if err != nil {
		t.Fatalf("LoadDHCPv4: %v", err)
	}
	a, ok := proto.AttrByName("Message-Type")
	if !ok {
		t.Fatal("Message-Type missing")
	}
	v, ok := a.EnumByName["Discover"]
	if !ok {
		t.Fatal("Discover enum missing")
	}
	if v != 99 {
		t.Fatalf("Discover = %d, want 99 (custom override)", v)
	}
}

// TestReplaceEmbeddedExcludesDefaults loads only a custom dictionary and
// verifies the embedded attrs are NOT present.
func TestReplaceEmbeddedExcludesDefaults(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "dictionary", `
BEGIN PROTOCOL DHCPv4 2
ATTRIBUTE Custom-Option 99 string
END PROTOCOL
`)
	proto, err := LoadDHCPv4(
		WithReplaceEmbedded(),
		WithCustomDicts(filepath.Join(dir, "dictionary")),
	)
	if err != nil {
		t.Fatalf("LoadDHCPv4: %v", err)
	}
	if _, ok := proto.AttrByName("Subnet-Mask"); ok {
		t.Fatal("Subnet-Mask should NOT be present in replace mode")
	}
	if _, ok := proto.AttrByName("Custom-Option"); !ok {
		t.Fatal("Custom-Option missing in replace mode")
	}
}

// TestDirectoryDictGlobsDictionaryStar confirms that pointing --dict at a
// directory loads only dictionary* files (not notes / scripts).
func TestDirectoryDictGlobsDictionaryStar(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "dictionary.foo", `
VENDOR Foo 11111
BEGIN-VENDOR Foo
ATTRIBUTE Foo-Option 1 string
END-VENDOR Foo
`)
	writeFile(t, dir, "dictionary.bar", `
VENDOR Bar 22222
BEGIN-VENDOR Bar
ATTRIBUTE Bar-Option 1 string
END-VENDOR Bar
`)
	writeFile(t, dir, "notes.txt", "this is not a dictionary")
	proto, err := LoadDHCPv4(WithCustomDicts(dir))
	if err != nil {
		t.Fatalf("LoadDHCPv4: %v", err)
	}
	if _, ok := proto.VendorsByName["Foo"]; !ok {
		t.Fatal("Foo vendor not loaded from directory")
	}
	if _, ok := proto.VendorsByName["Bar"]; !ok {
		t.Fatal("Bar vendor not loaded from directory")
	}
}

// TestProtocolSwitchInCustomErrors confirms a custom file declaring a
// different protocol-number than the already-loaded one fails clearly.
func TestProtocolSwitchInCustomErrors(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "dictionary.evil", `
BEGIN PROTOCOL DHCPv6 3
ATTRIBUTE Sneaky 99 string
END PROTOCOL
`)
	_, err := LoadDHCPv4(WithCustomDicts(filepath.Join(dir, "dictionary.evil")))
	if err == nil {
		t.Fatal("expected protocol-mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "BEGIN PROTOCOL DHCPv6") {
		t.Fatalf("error doesn't mention protocol mismatch: %v", err)
	}
}

// TestUnknownDictPathError verifies a missing --dict path produces a
// clear error.
func TestUnknownDictPathError(t *testing.T) {
	_, err := LoadDHCPv4(WithCustomDicts("/no/such/path/dictionary"))
	if err == nil {
		t.Fatal("expected error for missing path, got nil")
	}
	if !strings.Contains(err.Error(), "/no/such/path/dictionary") {
		t.Fatalf("error doesn't mention the bad path: %v", err)
	}
}

// TestEmptyDirectoryErrors confirms that pointing --dict at a directory
// with no dictionary* files produces a clear error.
func TestEmptyDirectoryErrors(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "notes.txt", "no dictionaries here")
	_, err := LoadDHCPv4(WithCustomDicts(dir))
	if err == nil {
		t.Fatal("expected error for empty dictionary directory, got nil")
	}
	if !strings.Contains(err.Error(), "no dictionary") {
		t.Fatalf("error doesn't mention missing dictionary files: %v", err)
	}
}
