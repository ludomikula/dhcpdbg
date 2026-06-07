package dict

import "embed"

// embeddedDicts contains the FreeRADIUS DHCPv4 and DHCPv6 dictionary trees
// copied verbatim from freeradius/share/dictionary/{dhcpv4,dhcpv6,freeradius}.
// The tree is read at startup; the binary carries no external files unless
// the caller passes a custom --dict path.
//
//go:embed embedded
var embeddedDicts embed.FS

// newEmbeddedSource returns the dictSource that wraps the binary's compiled-in
// dictionary tree. Used as the default when no --dict-replace is set.
func newEmbeddedSource() dictSource {
	return &embeddedSource{fs: embeddedDicts, root: "embedded"}
}
