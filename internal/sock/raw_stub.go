//go:build !linux

package sock

import (
	"errors"
	"net"
	"time"
)

// openRaw is unimplemented outside Linux; dhcpdbg is documented as Linux-only
// for raw mode (AF_PACKET is the only sane choice). UDP mode still works on
// every platform.
func openRaw(cfg Config) (Conn, error) {
	return nil, errors.New("raw socket mode is only supported on Linux; use --socket=udp")
}

func enableBroadcast(*net.UDPConn) error { return nil }

func setMulticastIface6(*net.UDPConn, string) error { return nil }

// keep the time import alive on non-linux builds where rawConn.Recv would use
// it; not strictly necessary but harmless.
var _ = time.Now
