//go:build linux

package sock

import "testing"

// TestRawConnSrcPortFallback proves the UDP source port written into
// the manually-built header falls back to the family-standard port
// when Config.SrcPort is left at zero, and otherwise honours the
// caller's override.
func TestRawConnSrcPortFallback(t *testing.T) {
	cases := []struct {
		family string
		srcSet int
		want   uint16
	}{
		{"udp4", 0, DefaultV4ClientPort},
		{"udp6", 0, DefaultV6ClientPort},
		{"udp4", 1068, 1068},
		{"udp6", 1546, 1546},
		// Defensive: a negative SrcPort would be rejected upstream in
		// main.go but the in-package helper must still produce a sane
		// port rather than overflowing through uint16().
		{"udp4", -1, DefaultV4ClientPort},
	}
	for _, tc := range cases {
		r := &rawConn{family: tc.family, srcPort: tc.srcSet}
		if got := r.srcPortFor(); got != tc.want {
			t.Errorf("family=%s srcSet=%d: srcPortFor() = %d, want %d",
				tc.family, tc.srcSet, got, tc.want)
		}
	}
}
