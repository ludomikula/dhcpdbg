package dict

import "embed"

// embeddedDicts contains the FreeRADIUS DHCPv4 and DHCPv6 dictionary trees
// copied verbatim from freeradius/share/dictionary/{dhcpv4,dhcpv6,freeradius}.
// The tree is read at startup; the binary carries no external files.
//
//go:embed embedded
var embeddedDicts embed.FS

func init() {
	dictFS = embeddedDicts
	dictRoot = "embedded"
}
