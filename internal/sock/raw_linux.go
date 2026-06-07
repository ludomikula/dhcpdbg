//go:build linux

package sock

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"
)

// openRaw builds an AF_PACKET DGRAM socket bound to cfg.Iface. AF_PACKET DGRAM
// gives us cooked layer-3 frames — kernel handles the Ethernet header — so we
// only need to assemble the IP+UDP header for DHCPv4 broadcast from 0.0.0.0,
// or an IPv6 link-local source for DHCPv6.
//
// Permission preflight: AF_PACKET requires CAP_NET_RAW (or root). We fail
// fast with a clear message rather than the bare EPERM the kernel returns.
func openRaw(cfg Config) (Conn, error) {
	if cfg.Iface == "" {
		return nil, errors.New("raw socket requires -i <iface>")
	}
	if os.Geteuid() != 0 && !hasNetRaw() {
		return nil, errors.New("raw socket requires CAP_NET_RAW (run as root or `setcap cap_net_raw+ep`)")
	}
	ifi, err := net.InterfaceByName(cfg.Iface)
	if err != nil {
		return nil, fmt.Errorf("interface %s: %v", cfg.Iface, err)
	}

	proto := uint16(syscall.ETH_P_IP)
	if cfg.Family == "udp6" {
		proto = uint16(syscall.ETH_P_IPV6)
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM, int(htons(proto)))
	if err != nil {
		return nil, fmt.Errorf("AF_PACKET socket: %v", err)
	}

	sll := &syscall.SockaddrLinklayer{
		Protocol: htons(proto),
		Ifindex:  ifi.Index,
	}
	if err := syscall.Bind(fd, sll); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("bind AF_PACKET: %v", err)
	}
	return &rawConn{fd: fd, iface: ifi, family: cfg.Family, srcPort: cfg.SrcPort}, nil
}

type rawConn struct {
	fd      int
	iface   *net.Interface
	family  string
	srcPort int // UDP source port; 0 means use the family default
}

// srcPortFor returns the configured source port, defaulting to 68 for
// "udp4" and 546 for "udp6" when the caller left it at 0.
func (r *rawConn) srcPortFor() uint16 {
	if r.srcPort > 0 {
		return uint16(r.srcPort)
	}
	if r.family == "udp4" {
		return DefaultV4ClientPort
	}
	return DefaultV6ClientPort
}

func (r *rawConn) SendTo(buf []byte, dst *net.UDPAddr) error {
	if r.family == "udp4" {
		return r.send4(buf, dst)
	}
	return r.send6(buf, dst)
}

// send4 wraps the DHCP payload in an IPv4 + UDP header and writes it to the
// link via SOCK_DGRAM (kernel adds the Ethernet header from the link-layer
// sockaddr). Source IP defaults to 0.0.0.0 — the canonical DHCPv4 client
// pre-lease behaviour.
func (r *rawConn) send4(payload []byte, dst *net.UDPAddr) error {
	srcIP := net.IPv4zero.To4()
	dstIP := dst.IP.To4()
	if dstIP == nil {
		return fmt.Errorf("send4: dst is not IPv4")
	}
	udpLen := 8 + len(payload)
	udp := make([]byte, udpLen)
	binary.BigEndian.PutUint16(udp[0:2], r.srcPortFor())
	binary.BigEndian.PutUint16(udp[2:4], uint16(dst.Port))
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	// UDP checksum optional for IPv4; set to 0.
	binary.BigEndian.PutUint16(udp[6:8], 0)
	copy(udp[8:], payload)

	ipLen := 20 + udpLen
	ip := make([]byte, 20)
	ip[0] = 0x45                                // ver 4, IHL 5
	ip[1] = 0                                   // DSCP/ECN
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipLen))
	binary.BigEndian.PutUint16(ip[4:6], 0)      // ID
	binary.BigEndian.PutUint16(ip[6:8], 0)      // flags/frag
	ip[8] = 64                                  // TTL
	ip[9] = syscall.IPPROTO_UDP
	binary.BigEndian.PutUint16(ip[10:12], 0)    // checksum (filled in)
	copy(ip[12:16], srcIP)
	copy(ip[16:20], dstIP)
	binary.BigEndian.PutUint16(ip[10:12], inetChecksum(ip))

	frame := append(ip, udp...)

	// Destination link-layer address: broadcast for limited bcast / netbcast,
	// otherwise zero (kernel ARP resolves).
	addr := &syscall.SockaddrLinklayer{
		Protocol: htons(uint16(syscall.ETH_P_IP)),
		Ifindex:  r.iface.Index,
		Halen:    6,
	}
	if dstIP.Equal(net.IPv4bcast) || dstIP[3] == 0xff {
		for i := 0; i < 6; i++ {
			addr.Addr[i] = 0xff
		}
	}
	return syscall.Sendto(r.fd, frame, 0, addr)
}

// send6 wraps the DHCPv6 payload in an IPv6 + UDP header. Source is the
// interface's first link-local address.
func (r *rawConn) send6(payload []byte, dst *net.UDPAddr) error {
	srcIP, err := firstLinkLocal(r.iface)
	if err != nil {
		return err
	}
	dstIP := dst.IP.To16()
	udpLen := 8 + len(payload)
	udp := make([]byte, udpLen)
	binary.BigEndian.PutUint16(udp[0:2], r.srcPortFor())
	binary.BigEndian.PutUint16(udp[2:4], uint16(dst.Port))
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	binary.BigEndian.PutUint16(udp[6:8], 0)
	copy(udp[8:], payload)

	// UDP6 checksum is mandatory; compute over pseudo-header.
	binary.BigEndian.PutUint16(udp[6:8], udp6Checksum(srcIP, dstIP, udp))

	ip := make([]byte, 40)
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], uint16(udpLen))
	ip[6] = syscall.IPPROTO_UDP
	ip[7] = 64
	copy(ip[8:24], srcIP)
	copy(ip[24:40], dstIP)
	frame := append(ip, udp...)

	addr := &syscall.SockaddrLinklayer{
		Protocol: htons(uint16(syscall.ETH_P_IPV6)),
		Ifindex:  r.iface.Index,
		Halen:    6,
	}
	// All-DHCP-relay-agents-and-servers multicast → 33:33:00:01:00:02
	if dstIP[0] == 0xff {
		addr.Addr[0] = 0x33
		addr.Addr[1] = 0x33
		addr.Addr[2] = dstIP[12]
		addr.Addr[3] = dstIP[13]
		addr.Addr[4] = dstIP[14]
		addr.Addr[5] = dstIP[15]
	}
	return syscall.Sendto(r.fd, frame, 0, addr)
}

func (r *rawConn) Recv(deadline time.Time) ([]byte, *net.UDPAddr, error) {
	// SO_RCVTIMEO for the deadline. For listen mode the caller passes a
	// far-future deadline.
	d := time.Until(deadline)
	if d <= 0 {
		return nil, nil, ErrTimeout
	}
	tv := syscall.NsecToTimeval(int64(d))
	if err := syscall.SetsockoptTimeval(r.fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return nil, nil, err
	}
	buf := make([]byte, 65536)
	n, _, err := syscall.Recvfrom(r.fd, buf, 0)
	if err != nil {
		if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, nil, ErrTimeout
		}
		return nil, nil, err
	}
	frame := buf[:n]
	// Strip IP+UDP headers if present (frame is layer-3 because of SOCK_DGRAM).
	if r.family == "udp4" {
		if len(frame) < 28 || frame[0]>>4 != 4 {
			return nil, nil, fmt.Errorf("raw recv: not IPv4")
		}
		ihl := int(frame[0]&0x0f) * 4
		if len(frame) < ihl+8 {
			return nil, nil, fmt.Errorf("raw recv: truncated IPv4")
		}
		udp := frame[ihl:]
		src := &net.UDPAddr{
			IP:   net.IP(frame[12:16]).To4(),
			Port: int(binary.BigEndian.Uint16(udp[0:2])),
		}
		return udp[8:], src, nil
	}
	// IPv6
	if len(frame) < 48 || frame[0]>>4 != 6 {
		return nil, nil, fmt.Errorf("raw recv: not IPv6")
	}
	udp := frame[40:]
	src := &net.UDPAddr{
		IP:   net.IP(frame[8:24]),
		Port: int(binary.BigEndian.Uint16(udp[0:2])),
	}
	return udp[8:], src, nil
}

func (r *rawConn) Close() error { return syscall.Close(r.fd) }

// htons converts host byte order to network byte order for a uint16.
func htons(v uint16) uint16 { return (v<<8)&0xff00 | (v>>8)&0x00ff }

// hasNetRaw checks /proc/self/status for the effective capability mask. A
// lightweight, no-cgo alternative to libcap.
func hasNetRaw() bool {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	const key = "CapEff:\t"
	for i := 0; i+len(key) < len(data); i++ {
		if string(data[i:i+len(key)]) == key {
			// Parse hex word after the key.
			line := data[i+len(key):]
			end := 0
			for end < len(line) && line[end] != '\n' {
				end++
			}
			mask, err := parseHex(string(line[:end]))
			if err != nil {
				return false
			}
			return mask&(1<<13) != 0 // CAP_NET_RAW
		}
	}
	return false
}

func parseHex(s string) (uint64, error) {
	var n uint64
	for i := 0; i < len(s); i++ {
		c := s[i]
		var d uint64
		switch {
		case c >= '0' && c <= '9':
			d = uint64(c - '0')
		case c >= 'a' && c <= 'f':
			d = uint64(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = uint64(c-'A') + 10
		default:
			return 0, fmt.Errorf("bad hex char %q", c)
		}
		n = n*16 + d
	}
	return n, nil
}

func firstLinkLocal(ifi *net.Interface) (net.IP, error) {
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, err
	}
	for _, a := range addrs {
		ip, _, err := net.ParseCIDR(a.String())
		if err != nil {
			continue
		}
		v6 := ip.To16()
		if v6 == nil || ip.To4() != nil {
			continue
		}
		if v6[0] == 0xfe && v6[1]&0xc0 == 0x80 {
			return v6, nil
		}
	}
	return nil, fmt.Errorf("interface %s: no IPv6 link-local address", ifi.Name)
}

func enableBroadcast(c *net.UDPConn) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
	}); err != nil {
		return err
	}
	return sockErr
}

func setMulticastIface6(c *net.UDPConn, name string) error {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return err
	}
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		// IPV6_MULTICAST_IF takes an int (ifindex).
		v := int32(ifi.Index)
		sockErr = syscallSetsockoptInt(int(fd), syscall.IPPROTO_IPV6, 17 /* IPV6_MULTICAST_IF */, int(v))
	}); err != nil {
		return err
	}
	return sockErr
}

func syscallSetsockoptInt(fd, level, opt, value int) error {
	v := int32(value)
	_, _, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT,
		uintptr(fd), uintptr(level), uintptr(opt),
		uintptr(unsafe.Pointer(&v)), unsafe.Sizeof(v), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// inetChecksum computes the standard 16-bit one's complement checksum used by
// IPv4 / TCP / UDP.
func inetChecksum(b []byte) uint16 {
	sum := uint32(0)
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// udp6Checksum computes the UDPv6 checksum including the IPv6 pseudo-header
// (RFC 8200 §8.1).
func udp6Checksum(src, dst, udp []byte) uint16 {
	pseudo := make([]byte, 40+len(udp))
	copy(pseudo[0:16], src)
	copy(pseudo[16:32], dst)
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(udp)))
	pseudo[39] = syscall.IPPROTO_UDP
	copy(pseudo[40:], udp)
	return inetChecksum(pseudo)
}
