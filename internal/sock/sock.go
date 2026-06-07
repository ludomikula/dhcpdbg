// Package sock owns the socket-level send/receive for dhcpdbg. Two backends
// are provided:
//
//   - UDP: a vanilla net.UDPConn, source IP picked by the kernel. Adequate
//     for unicast renews/informs and for talking to a relay. Broadcast is
//     enabled where applicable.
//
//   - Raw: an AF_PACKET DGRAM socket (Linux only), used when the source IP
//     must be 0.0.0.0 / link-local before a lease exists. Requires
//     CAP_NET_RAW (or root) and a bound interface.
//
// Both backends share a common Conn interface so the request loop and listen
// loop don't care which is in use.
package sock

import (
	"errors"
	"fmt"
	"net"
	"os"
	"time"
)

// Mode selects which backend Open returns.
type Mode int

const (
	ModeUDP Mode = iota
	ModeRaw
)

// Conn is the small interface the request/listen loops drive.
type Conn interface {
	// SendTo writes one packet to dst.
	SendTo(buf []byte, dst *net.UDPAddr) error
	// Recv waits up to deadline for one inbound packet. Returns (payload, src, error).
	Recv(deadline time.Time) ([]byte, *net.UDPAddr, error)
	// Close releases the underlying socket.
	Close() error
}

// Config drives Open. Family is "udp4" or "udp6". Bind is the local address
// (e.g. ":68" for DHCPv4 client, "[::]:546" for DHCPv6).
type Config struct {
	Mode       Mode
	Family     string // "udp4" or "udp6"
	Bind       string
	// SrcPort is the UDP source port written into the manually-built
	// IPv4/IPv6 + UDP header when Mode == ModeRaw. The kernel does not
	// know about the AF_PACKET DGRAM source port, so the caller must
	// supply it. Ignored for ModeUDP (the bind address determines the
	// source there). Zero means "use the family default" — 68 for
	// "udp4", 546 for "udp6".
	SrcPort    int
	Iface      string // required for ModeRaw
	Broadcast  bool   // set SO_BROADCAST on the UDP socket
	MulticastIface string // for DHCPv6 multicast egress (sets IPV6_MULTICAST_IF)
}

// Standard DHCP client UDP ports — used as the raw-socket SrcPort
// fallback when Config.SrcPort is 0.
const (
	DefaultV4ClientPort = 68
	DefaultV6ClientPort = 546
)

// Open returns a Conn matching cfg, validating prerequisites up front.
func Open(cfg Config) (Conn, error) {
	switch cfg.Mode {
	case ModeUDP:
		return openUDP(cfg)
	case ModeRaw:
		return openRaw(cfg)
	}
	return nil, fmt.Errorf("unknown socket mode")
}

// --- UDP backend ---

type udpConn struct {
	conn *net.UDPConn
}

func openUDP(cfg Config) (Conn, error) {
	addr, err := net.ResolveUDPAddr(cfg.Family, cfg.Bind)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %v", cfg.Bind, err)
	}
	conn, err := net.ListenUDP(cfg.Family, addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %v", cfg.Bind, err)
	}
	if cfg.Broadcast {
		if err := enableBroadcast(conn); err != nil {
			conn.Close()
			return nil, err
		}
	}
	if cfg.MulticastIface != "" && cfg.Family == "udp6" {
		if err := setMulticastIface6(conn, cfg.MulticastIface); err != nil {
			// Not fatal — kernel default may already DTRT.
			fmt.Fprintf(os.Stderr, "dhcpdbg: warn: setting IPV6_MULTICAST_IF: %v\n", err)
		}
	}
	return &udpConn{conn: conn}, nil
}

func (u *udpConn) SendTo(buf []byte, dst *net.UDPAddr) error {
	_, err := u.conn.WriteToUDP(buf, dst)
	return err
}

func (u *udpConn) Recv(deadline time.Time) ([]byte, *net.UDPAddr, error) {
	if err := u.conn.SetReadDeadline(deadline); err != nil {
		return nil, nil, err
	}
	buf := make([]byte, 65536)
	n, src, err := u.conn.ReadFromUDP(buf)
	if err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return nil, nil, ErrTimeout
		}
		return nil, nil, err
	}
	return buf[:n], src, nil
}

func (u *udpConn) Close() error { return u.conn.Close() }

// ErrTimeout is returned by Recv when no packet arrived before the deadline.
var ErrTimeout = errors.New("recv timeout")
