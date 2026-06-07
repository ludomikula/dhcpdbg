// Package cli ties the dictionary, parser, codec, and socket layers together
// into the two dhcpdbg operating modes: request (send-and-wait) and listen
// (passive sniffer). The CLI flag parsing lives in main; this package is
// what main hands the parsed Options to.
package cli

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ludomikula/dhcpdbg/internal/attrs"
	"github.com/ludomikula/dhcpdbg/internal/dict"
	"github.com/ludomikula/dhcpdbg/internal/info"
	"github.com/ludomikula/dhcpdbg/internal/sock"
	"github.com/ludomikula/dhcpdbg/internal/wire4"
	"github.com/ludomikula/dhcpdbg/internal/wire6"
)

// Family selects DHCPv4 or DHCPv6.
type Family int

const (
	V4 Family = 4
	V6 Family = 6
)

// Mode is the high-level operating mode.
type Mode int

const (
	ModeRequest Mode = iota
	ModeListen
	// ModeInfo is the dictionary-inspection mode. It loads the protocol
	// but does not open a socket — it just renders the dictionary tree
	// through internal/info per the Info* fields below.
	ModeInfo
)

// InfoMode selects which info-mode rendering to run.
type InfoMode int

const (
	// InfoNone is the default zero value; ModeInfo with InfoNone is invalid.
	InfoNone InfoMode = iota
	// InfoListDicts lists every loaded dictionary file in load order.
	InfoListDicts
	// InfoPrintDict prints the full friendly dictionary dump (or a
	// filtered subset when InfoVendors is non-empty).
	InfoPrintDict
)

// Options is the fully-resolved CLI input — main fills this in and calls Run.
type Options struct {
	Family   Family
	Mode     Mode
	SockMode sock.Mode

	MsgTypeName string // -t value (case-insensitive name from dictionary)

	Server     string // "1.2.3.4" or "1.2.3.4:67" — may be empty for defaults
	Iface      string
	Retries    int
	Timeout    time.Duration
	InputPath  string // "" -> stdin
	Verbosity  int    // -x / -xx

	// DictPaths are additional FreeRADIUS-syntax dictionary files or
	// directories layered on top of the embedded defaults. Repeatable via
	// --dict on the CLI.
	DictPaths []string
	// DictReplace skips loading the embedded FreeRADIUS dictionaries —
	// only the files in DictPaths are loaded. Useful for fully-custom
	// deployments.
	DictReplace bool
	// DecodeOption43 is the vendor name (under Decoded-Option-43) the
	// decoder should walk an option-43 payload against. When empty,
	// option 43 stays opaque (Vendor-Specific-Options = 0x...).
	DecodeOption43 string

	// Info* fields drive ModeInfo. Ignored in request / listen modes.
	InfoMode    InfoMode
	InfoVendors []string
	// InfoJSON switches the info renderer from text to JSON. The text
	// renderer is the default.
	InfoJSON bool

	Stdout io.Writer
	Stderr io.Writer
}

// Run executes the configured operation. Returns 0 on success, non-zero on
// failure (timeout, NAK, parse error, DHCPv6 non-Success status).
func Run(opts Options) int {
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}

	proto, err := loadProto(opts.Family, opts)
	if err != nil {
		fmt.Fprintf(opts.Stderr, "dhcpdbg: %v\n", err)
		return 1
	}

	switch opts.Mode {
	case ModeInfo:
		return runInfo(opts, proto)
	case ModeListen:
		return runListen(opts, proto)
	default:
		return runRequest(opts, proto)
	}
}

// runInfo renders the loaded protocol's dictionary tree through the
// internal/info package and exits. It opens no sockets and reads no
// input file.
func runInfo(opts Options, proto *dict.Protocol) int {
	fmtSel := info.FormatText
	if opts.InfoJSON {
		fmtSel = info.FormatJSON
	}
	var err error
	switch opts.InfoMode {
	case InfoListDicts:
		err = info.ListDicts(opts.Stdout, proto, fmtSel)
	case InfoPrintDict:
		err = info.PrintDict(opts.Stdout, proto, opts.InfoVendors, fmtSel)
	default:
		fmt.Fprintln(opts.Stderr, "dhcpdbg: no info action selected")
		return 2
	}
	if err != nil {
		fmt.Fprintf(opts.Stderr, "dhcpdbg: %v\n", err)
		return 2
	}
	return 0
}

func loadProto(f Family, opts Options) (*dict.Protocol, error) {
	var dictOpts []dict.LoadOption
	if len(opts.DictPaths) > 0 {
		dictOpts = append(dictOpts, dict.WithCustomDicts(opts.DictPaths...))
	}
	if opts.DictReplace {
		dictOpts = append(dictOpts, dict.WithReplaceEmbedded())
	}
	if f == V4 {
		proto, err := dict.LoadDHCPv4(dictOpts...)
		if err != nil {
			return nil, err
		}
		wire4.SynthesizeStructured(proto)
		return proto, nil
	}
	return dict.LoadDHCPv6(dictOpts...)
}

func runRequest(opts Options, proto *dict.Protocol) int {
	in, err := openInput(opts.InputPath)
	if err != nil {
		fmt.Fprintf(opts.Stderr, "dhcpdbg: %v\n", err)
		return 2
	}
	defer in.Close()

	records, err := attrs.ReadList(in, proto)
	if err != nil {
		fmt.Fprintf(opts.Stderr, "dhcpdbg: %v\n", err)
		return 2
	}
	pairs := records[0]
	// Apply -t (message type name) if the input didn't already set a
	// Packet-Type / Message-Type.
	pairs = applyMsgType(pairs, opts.MsgTypeName, opts.Family, proto)
	// Ensure an XID/transaction ID is present.
	pairs = ensureXID(pairs, opts.Family, proto)

	// Encode.
	var wire []byte
	switch opts.Family {
	case V4:
		wire, err = wire4.Encode(pairs, proto)
	case V6:
		wire, err = wire6.Encode(pairs, proto)
	}
	if err != nil {
		fmt.Fprintf(opts.Stderr, "dhcpdbg: encode: %v\n", err)
		return 2
	}
	if opts.Verbosity >= 2 {
		dumpHex(opts.Stderr, "send", wire)
	}

	dst, err := resolveServer(opts.Family, opts.Server)
	if err != nil {
		fmt.Fprintf(opts.Stderr, "dhcpdbg: %v\n", err)
		return 2
	}

	cfg := sock.Config{
		Mode:      opts.SockMode,
		Family:    udpFamily(opts.Family),
		Bind:      defaultBind(opts.Family, opts.SockMode),
		Iface:     opts.Iface,
		Broadcast: opts.Family == V4,
	}
	if opts.Family == V6 && opts.Iface != "" {
		cfg.MulticastIface = opts.Iface
	}
	conn, err := sock.Open(cfg)
	if err != nil {
		fmt.Fprintf(opts.Stderr, "dhcpdbg: open socket: %v\n", err)
		return 3
	}
	defer conn.Close()

	for attempt := 0; attempt <= opts.Retries; attempt++ {
		if err := conn.SendTo(wire, dst); err != nil {
			fmt.Fprintf(opts.Stderr, "dhcpdbg: send: %v\n", err)
			return 3
		}
		if opts.Verbosity >= 1 {
			fmt.Fprintf(opts.Stderr, "dhcpdbg: sent %d bytes to %s\n", len(wire), dst.String())
		}
		reply, src, err := waitForReply(conn, opts.Timeout, wire, opts.Family, proto, opts)
		if err == sock.ErrTimeout {
			if attempt < opts.Retries {
				fmt.Fprintf(opts.Stderr, "dhcpdbg: timeout, retry %d/%d\n", attempt+1, opts.Retries)
				continue
			}
			fmt.Fprintln(opts.Stderr, "dhcpdbg: timeout")
			return 4
		}
		if err != nil {
			fmt.Fprintf(opts.Stderr, "dhcpdbg: recv: %v\n", err)
			return 3
		}
		if opts.Verbosity >= 1 {
			fmt.Fprintf(opts.Stderr, "dhcpdbg: received %d bytes from %s\n", len(reply.raw), src.String())
		}
		if opts.Verbosity >= 2 {
			dumpHex(opts.Stderr, "recv", reply.raw)
		}
		printRecord(opts.Stdout, reply.pairs)
		return reply.exitCode
	}
	return 4
}

func runListen(opts Options, proto *dict.Protocol) int {
	cfg := sock.Config{
		Mode:      opts.SockMode,
		Family:    udpFamily(opts.Family),
		Bind:      defaultListenBind(opts.Family),
		Iface:     opts.Iface,
		Broadcast: opts.Family == V4,
	}
	conn, err := sock.Open(cfg)
	if err != nil {
		fmt.Fprintf(opts.Stderr, "dhcpdbg: open socket: %v\n", err)
		return 3
	}
	defer conn.Close()

	sigC := make(chan os.Signal, 1)
	signal.Notify(sigC, syscall.SIGINT, syscall.SIGTERM)

	fmt.Fprintf(opts.Stderr, "dhcpdbg: listening on %s, ctrl-c to stop\n", cfg.Bind)
	for {
		select {
		case <-sigC:
			return 0
		default:
		}
		buf, src, err := conn.Recv(time.Now().Add(1 * time.Second))
		if err == sock.ErrTimeout {
			continue
		}
		if err != nil {
			fmt.Fprintf(opts.Stderr, "dhcpdbg: recv: %v\n", err)
			return 3
		}
		pairs, _, err := decodeAny(opts.Family, buf, proto, opts)
		if err != nil {
			fmt.Fprintf(opts.Stderr, "dhcpdbg: decode: %v\n", err)
			continue
		}
		fmt.Fprintf(opts.Stdout, "# from %s\n", src.String())
		printRecord(opts.Stdout, pairs)
		fmt.Fprintln(opts.Stdout)
	}
}

type incoming struct {
	pairs    []attrs.Pair
	raw      []byte
	exitCode int
}

func waitForReply(conn sock.Conn, timeout time.Duration, sent []byte, family Family, proto *dict.Protocol, opts Options) (*incoming, *net.UDPAddr, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		buf, src, err := conn.Recv(deadline)
		if err != nil {
			return nil, nil, err
		}
		pairs, ec, err := decodeAny(family, buf, proto, opts)
		if err != nil {
			if opts.Verbosity >= 1 {
				fmt.Fprintf(os.Stderr, "dhcpdbg: skipping malformed packet: %v\n", err)
			}
			continue
		}
		if family == V4 && !matchesXID4(sent, buf) {
			continue
		}
		if family == V6 && !matchesTxn6(sent, buf) {
			continue
		}
		return &incoming{pairs: pairs, raw: buf, exitCode: ec}, src, nil
	}
	return nil, nil, sock.ErrTimeout
}

// decodeAny dispatches to the right wire package and computes the exit-code
// per the spec: NAK / non-Success DHCPv6 status -> non-zero.
func decodeAny(family Family, buf []byte, proto *dict.Protocol, opts Options) ([]attrs.Pair, int, error) {
	if family == V4 {
		pkt, err := wire4.Decode(buf, proto, opts.DecodeOption43)
		if err != nil {
			return nil, 0, err
		}
		if pkt.MessageType == 6 { // NAK
			return pkt.Pairs, 5, nil
		}
		return pkt.Pairs, 0, nil
	}
	pkt, err := wire6.Decode(buf, proto)
	if err != nil {
		return nil, 0, err
	}
	// Scan for Status-Code option (code 13).
	for _, p := range pkt.Pairs {
		if p.Attr != nil && p.Attr.Code == 13 && p.Attr.Vendor == 0 {
			if len(p.Value.Bytes) >= 2 {
				s := binary.BigEndian.Uint16(p.Value.Bytes[:2])
				if s != 0 {
					return pkt.Pairs, 5, nil
				}
			}
		}
	}
	return pkt.Pairs, 0, nil
}

func matchesXID4(sent, recv []byte) bool {
	if len(sent) < 8 || len(recv) < 8 {
		return false
	}
	return binary.BigEndian.Uint32(sent[4:8]) == binary.BigEndian.Uint32(recv[4:8])
}

func matchesTxn6(sent, recv []byte) bool {
	if len(sent) < 4 || len(recv) < 4 {
		return false
	}
	return sent[1] == recv[1] && sent[2] == recv[2] && sent[3] == recv[3]
}

func printRecord(w io.Writer, pairs []attrs.Pair) {
	_ = attrs.WriteList(w, pairs)
}

func openInput(p string) (io.ReadCloser, error) {
	if p == "" {
		return io.NopCloser(os.Stdin), nil
	}
	return os.Open(p)
}

func applyMsgType(pairs []attrs.Pair, name string, family Family, proto *dict.Protocol) []attrs.Pair {
	if name == "" {
		return pairs
	}
	// Already set?
	for _, p := range pairs {
		if p.Attr == nil {
			continue
		}
		if family == V4 && (p.Attr.Code == 53 || p.Attr.Code == 273) {
			return pairs
		}
		if family == V6 && p.Attr.Code == 65536 {
			return pairs
		}
	}
	var ptName string
	if family == V4 {
		ptName = "Packet-Type"
	} else {
		ptName = "Packet-Type"
	}
	a, ok := proto.AttrByName(ptName)
	if !ok {
		return pairs
	}
	// Look up the enum value (case-insensitive).
	for ename, evalue := range a.EnumByName {
		if strings.EqualFold(ename, name) {
			return append(pairs, attrs.Pair{Attr: a, Value: attrs.Value{Type: a.Type, Uint: evalue}})
		}
	}
	return pairs
}

// ensureXID adds a random transaction ID if the user didn't specify one.
// DHCPv4 uses a 32-bit xid; DHCPv6 uses a 24-bit transaction id stored in 3
// octets.
func ensureXID(pairs []attrs.Pair, family Family, proto *dict.Protocol) []attrs.Pair {
	if family == V4 {
		for _, p := range pairs {
			if p.Attr != nil && p.Attr.Code == 260 { // Transaction-Id
				return pairs
			}
		}
		var b [4]byte
		_, _ = rand.Read(b[:])
		xid := binary.BigEndian.Uint32(b[:])
		if a, ok := proto.AttrByName("Transaction-Id"); ok {
			return append(pairs, attrs.Pair{Attr: a, Value: attrs.Value{Type: dict.TypeUint32, Uint: uint64(xid)}})
		}
		return pairs
	}
	for _, p := range pairs {
		if p.Attr != nil && p.Attr.Code == 65537 {
			return pairs
		}
	}
	var b [3]byte
	_, _ = rand.Read(b[:])
	if a, ok := proto.AttrByName("Transaction-ID"); ok {
		return append(pairs, attrs.Pair{Attr: a, Value: attrs.Value{Type: dict.TypeOctets, Bytes: b[:]}})
	}
	return pairs
}

func resolveServer(family Family, s string) (*net.UDPAddr, error) {
	if family == V4 {
		if s == "" {
			s = "255.255.255.255:67"
		} else if _, _, err := net.SplitHostPort(s); err != nil {
			s = s + ":67"
		}
		return net.ResolveUDPAddr("udp4", s)
	}
	if s == "" {
		s = "[ff02::1:2]:547"
	} else if !strings.HasPrefix(s, "[") && !strings.Contains(s, "]:") {
		s = "[" + s + "]:547"
	}
	return net.ResolveUDPAddr("udp6", s)
}

func udpFamily(f Family) string {
	if f == V4 {
		return "udp4"
	}
	return "udp6"
}

func defaultBind(f Family, m sock.Mode) string {
	if f == V4 {
		// Client port 68 for DHCPv4.
		return "0.0.0.0:68"
	}
	return "[::]:546"
}

func defaultListenBind(f Family) string {
	if f == V4 {
		// Listen on the server port to catch OFFER/ACK packets flowing
		// from a server to a client. Tweak with -s if needed.
		return "0.0.0.0:68"
	}
	return "[::]:546"
}

func dumpHex(w io.Writer, label string, b []byte) {
	fmt.Fprintf(w, "--- %s (%d bytes) ---\n%s\n", label, len(b), hex.Dump(b))
}
