package cli

import (
	"testing"

	"github.com/ludomikula/dhcpdbg/internal/sock"
)

// TestDefaultClientPort spot-checks the per-family fallback used by both
// defaultBind/defaultListenBind and the raw socket's UDP source.
func TestDefaultClientPort(t *testing.T) {
	if got, want := defaultClientPort(V4), defaultV4ClientPort; got != want {
		t.Errorf("defaultClientPort(V4) = %d, want %d", got, want)
	}
	if got, want := defaultClientPort(V6), defaultV6ClientPort; got != want {
		t.Errorf("defaultClientPort(V6) = %d, want %d", got, want)
	}
	// The CLI default constants must match the sock package's exported
	// fallback constants — they are documented as the same numbers and
	// the raw-socket path uses sock.DefaultV*ClientPort when SrcPort==0.
	if defaultV4ClientPort != sock.DefaultV4ClientPort {
		t.Errorf("cli/sock V4 default mismatch: cli=%d sock=%d", defaultV4ClientPort, sock.DefaultV4ClientPort)
	}
	if defaultV6ClientPort != sock.DefaultV6ClientPort {
		t.Errorf("cli/sock V6 default mismatch: cli=%d sock=%d", defaultV6ClientPort, sock.DefaultV6ClientPort)
	}
}

// TestEffectiveBindPort exercises the override-vs-default logic that
// feeds both the bind string and sock.Config.SrcPort.
func TestEffectiveBindPort(t *testing.T) {
	cases := []struct {
		name     string
		family   Family
		override int
		want     int
	}{
		{"v4 default", V4, 0, defaultV4ClientPort},
		{"v6 default", V6, 0, defaultV6ClientPort},
		{"v4 overridden", V4, 1068, 1068},
		{"v6 overridden", V6, 1546, 1546},
		// Negative override would have been rejected by main.go; the
		// helper should still fall back rather than emit a negative
		// port. (Defensive — internal contract is non-negative.)
		{"v4 negative falls back", V4, -1, defaultV4ClientPort},
	}
	for _, tc := range cases {
		if got := effectiveBindPort(tc.family, tc.override); got != tc.want {
			t.Errorf("%s: effectiveBindPort(%d, %d) = %d, want %d",
				tc.name, tc.family, tc.override, got, tc.want)
		}
	}
}

// TestDefaultBindRendersFamilyAddress checks the bind string format for
// every (family, override) combination — request mode binds here.
func TestDefaultBindRendersFamilyAddress(t *testing.T) {
	cases := []struct {
		family   Family
		override int
		want     string
	}{
		{V4, 0, "0.0.0.0:68"},
		{V6, 0, "[::]:546"},
		{V4, 1068, "0.0.0.0:1068"},
		{V6, 1546, "[::]:1546"},
	}
	for _, tc := range cases {
		got := defaultBind(tc.family, sock.ModeUDP, tc.override)
		if got != tc.want {
			t.Errorf("defaultBind(%d, _, %d) = %q, want %q",
				tc.family, tc.override, got, tc.want)
		}
		// Listen path must agree — both helpers share the override logic.
		gotListen := defaultListenBind(tc.family, tc.override)
		if gotListen != tc.want {
			t.Errorf("defaultListenBind(%d, %d) = %q, want %q",
				tc.family, tc.override, gotListen, tc.want)
		}
	}
}
