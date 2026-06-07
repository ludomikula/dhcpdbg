package cli

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/ludomikula/dhcpdbg/internal/attrs"
	"github.com/ludomikula/dhcpdbg/internal/dict"
	"github.com/ludomikula/dhcpdbg/internal/pcap"
	"github.com/ludomikula/dhcpdbg/internal/wire4"
	"github.com/ludomikula/dhcpdbg/internal/wire6"
)

// runReplayPcap reads pcap/pcapng input, decodes every DHCP packet via
// the wire codecs, optionally filters, and prints either as readable
// FreeRADIUS attribute notation or as NDJSON. The function ignores any
// `Mode != ModeReplayPcap`; main wires us through Run.
//
// Behaviour by user-answered question (in plan):
//   - both libpcap + pcapng formats are accepted (auto-detected)
//   - timestamp format is configurable via opts.Timestamp
//   - decode errors are ALWAYS shown (the offending packet is emitted
//     with a `# decode failed: ...` line in place of the pairs)
//   - DHCP-port packets that decode as gibberish (unrecognised family)
//     emit a `# unknown` line — never silently dropped
//   - --filter expression narrows the printed stream
func runReplayPcap(opts Options) int {
	rd, closer, err := openPcapSource(opts)
	if err != nil {
		fmt.Fprintf(opts.Stderr, "dhcpdbg: %v\n", err)
		return 3
	}
	if closer != nil {
		defer closer.Close()
	}
	reader, err := pcap.NewReader(rd)
	if err != nil {
		fmt.Fprintf(opts.Stderr, "dhcpdbg: %v\n", err)
		return 3
	}

	// Load whichever protocol(s) the run might need. When the user
	// pinned -4/-6 we save the parse cost on the other one.
	var proto4, proto6 *dict.Protocol
	if opts.Family == 0 || opts.Family == V4 {
		if p, err := loadProto(V4, opts); err == nil {
			proto4 = p
			wire4.SynthesizeStructured(proto4)
		} else {
			fmt.Fprintf(opts.Stderr, "dhcpdbg: load DHCPv4 dictionary: %v\n", err)
			return 1
		}
	}
	if opts.Family == 0 || opts.Family == V6 {
		if p, err := loadProto(V6, opts); err == nil {
			proto6 = p
		} else {
			fmt.Fprintf(opts.Stderr, "dhcpdbg: load DHCPv6 dictionary: %v\n", err)
			return 1
		}
	}

	// firstTS is used by --timestamp=relative; set on the first
	// successfully decoded packet.
	var firstTS time.Time

	for {
		frame, err := reader.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return 0
			}
			// Per-packet non-fatal error — surface and keep going.
			fmt.Fprintf(opts.Stderr, "dhcpdbg: %v\n", err)
			continue
		}
		// Family filter from -4/-6.
		if opts.Family != 0 && int(opts.Family) != int(frame.Family) {
			continue
		}
		// Decode against the right protocol.
		var pairs []attrs.Pair
		var decodeErr error
		switch frame.Family {
		case pcap.FamilyV4:
			if proto4 != nil {
				pkt, derr := wire4.Decode(frame.Payload, proto4, opts.DecodeOption43)
				if derr != nil {
					decodeErr = derr
				} else {
					pairs = pkt.Pairs
				}
			}
		case pcap.FamilyV6:
			if proto6 != nil {
				pkt, derr := wire6.Decode(frame.Payload, proto6)
				if derr != nil {
					decodeErr = derr
				} else {
					pairs = pkt.Pairs
				}
			}
		}

		// Run the filter once the pairs are known (filter clauses can
		// reference attribute values, so we must decode first).
		if !opts.ReplayFilter.IsZero() {
			proto := proto4
			if frame.Family == pcap.FamilyV6 {
				proto = proto6
			}
			if !opts.ReplayFilter.Match(frame, pairs, proto) {
				continue
			}
		}

		if firstTS.IsZero() {
			firstTS = frame.Timestamp
		}
		if opts.ReplayJSON {
			if err := emitJSON(opts.Stdout, frame, pairs, decodeErr); err != nil {
				fmt.Fprintf(opts.Stderr, "dhcpdbg: emit json: %v\n", err)
				return 3
			}
		} else {
			emitText(opts.Stdout, frame, pairs, decodeErr, opts.Timestamp, firstTS, opts.Verbosity)
		}
	}
}

// openPcapSource resolves opts.PcapPath / opts.PcapStream to an io.Reader.
// The returned io.Closer is non-nil only when we opened a file ourselves.
func openPcapSource(opts Options) (io.Reader, io.Closer, error) {
	if opts.PcapStream != nil {
		return opts.PcapStream, nil, nil
	}
	switch opts.PcapPath {
	case "":
		return nil, nil, errors.New("replay mode requires --replay-pcap PATH (or - for stdin)")
	case "-":
		return os.Stdin, nil, nil
	}
	f, err := os.Open(opts.PcapPath)
	if err != nil {
		return nil, nil, fmt.Errorf("open %s: %w", opts.PcapPath, err)
	}
	return f, f, nil
}

// formatTimestamp renders frame.Timestamp per the chosen TimestampFormat.
// Empty timestamps (a SPB block has no timestamp) render as "-".
func formatTimestamp(ts, first time.Time, mode TimestampFormat) string {
	if ts.IsZero() {
		return "-"
	}
	switch mode {
	case TimestampUTC:
		return ts.UTC().Format("2006-01-02T15:04:05.000000Z")
	case TimestampRelative:
		delta := ts.Sub(first)
		// Always positive for the first packet (delta == 0).
		return fmt.Sprintf("+%011.6fs", delta.Seconds())
	default: // TimestampLocal
		return ts.Local().Format("2006-01-02 15:04:05.000000")
	}
}

// emitText writes one packet's record in human-readable form. The leading
// `#`-prefixed comment lists timestamp, endpoints, family and capture
// length; the body is the standard attrs.WriteList output (round-trippable
// through ReadList). Decode errors replace the body with `# decode
// failed: ...`; per the design they're always shown.
func emitText(
	w io.Writer, frame *pcap.Frame, pairs []attrs.Pair, decodeErr error,
	tsMode TimestampFormat, firstTS time.Time, verbosity int,
) {
	ts := formatTimestamp(frame.Timestamp, firstTS, tsMode)
	famLabel := frame.Family.String()
	trunc := ""
	if frame.Truncated {
		trunc = ", truncated"
	}
	fmt.Fprintf(w, "# %s  %s:%d → %s:%d  (%s, %d bytes%s)\n",
		ts,
		ipString(frame.SrcIP), frame.SrcPort,
		ipString(frame.DstIP), frame.DstPort,
		famLabel, frame.Origlen, trunc,
	)
	if decodeErr != nil {
		fmt.Fprintf(w, "# decode failed: %v\n", decodeErr)
		if verbosity >= 2 {
			fmt.Fprintf(w, "# payload (%d bytes):\n%s", len(frame.Payload), hex.Dump(frame.Payload))
		}
		fmt.Fprintln(w)
		return
	}
	if len(pairs) == 0 {
		// Decoded to nothing — unusual, but flag it so the user sees
		// the packet existed.
		fmt.Fprintln(w, "# unknown: no attributes decoded")
		fmt.Fprintln(w)
		return
	}
	_ = attrs.WriteList(w, pairs)
	fmt.Fprintln(w)
}

// emitJSON writes one NDJSON record (one line, trailing newline). The
// shape is stable and documented in the README's filter / output table.
func emitJSON(w io.Writer, frame *pcap.Frame, pairs []attrs.Pair, decodeErr error) error {
	obj := map[string]any{
		"timestamp": frame.Timestamp.UTC().Format(time.RFC3339Nano),
		"src":       fmt.Sprintf("%s:%d", ipString(frame.SrcIP), frame.SrcPort),
		"dst":       fmt.Sprintf("%s:%d", ipString(frame.DstIP), frame.DstPort),
		"family":    frame.Family.String(),
		"caplen":    frame.Caplen,
		"origlen":   frame.Origlen,
		"truncated": frame.Truncated,
	}
	if decodeErr != nil {
		obj["error"] = decodeErr.Error()
	} else {
		obj["message_type"] = messageTypeName(pairs)
		obj["pairs"] = pairsToJSON(pairs)
	}
	b, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = w.Write(b)
	return err
}

// pairsToJSON renders a Pair list into a stable map[name]value form for
// NDJSON output. Repeated attribute names collapse into a list (preserves
// PRL arrays etc.); structured values use the same dotted-form keys
// WriteList prints (`IA-NA.IAID`, `Decoded-Option-43.Acme.Image-Path`).
func pairsToJSON(pairs []attrs.Pair) map[string]any {
	out := map[string]any{}
	for _, p := range pairs {
		if p.Attr == nil {
			continue
		}
		switch p.Value.Type {
		case dict.TypeStruct, dict.TypeUnion, dict.TypeGroup, dict.TypeTLV, dict.TypeVSA:
			// Use the WriteList expansion so structured options come out
			// with dotted-key paths consistent with the text form.
			var buf jsonLineBuf
			_ = attrs.WriteList(&buf, []attrs.Pair{p})
			for _, kv := range buf.lines {
				putIntoMap(out, kv.key, kv.value)
			}
		default:
			putIntoMap(out, p.Attr.Name, attrs.Format(p.Attr, p.Value))
		}
	}
	return out
}

// putIntoMap stores key→value, promoting to a slice on the second insert
// with the same key (array attributes such as Parameter-Request-List).
func putIntoMap(m map[string]any, key, value string) {
	if existing, ok := m[key]; ok {
		switch v := existing.(type) {
		case []string:
			m[key] = append(v, value)
		case string:
			m[key] = []string{v, value}
		default:
			m[key] = value
		}
		return
	}
	m[key] = value
}

// jsonLineBuf is a tiny io.Writer that captures attrs.WriteList output
// line by line so emitJSON can recover the dotted-key form without
// re-implementing WriteList.
type jsonLineBuf struct {
	pending []byte
	lines   []struct{ key, value string }
}

func (b *jsonLineBuf) Write(p []byte) (int, error) {
	b.pending = append(b.pending, p...)
	for {
		i := indexByte(b.pending, '\n')
		if i < 0 {
			return len(p), nil
		}
		line := string(b.pending[:i])
		b.pending = b.pending[i+1:]
		if k, v, ok := splitOnEquals(line); ok {
			b.lines = append(b.lines, struct{ key, value string }{k, v})
		}
	}
}

func indexByte(s []byte, c byte) int {
	for i := range s {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func splitOnEquals(s string) (string, string, bool) {
	eq := strings.Index(s, " = ")
	if eq < 0 {
		return "", "", false
	}
	return strings.TrimSpace(s[:eq]), strings.TrimSpace(s[eq+3:]), true
}

// messageTypeName extracts a human-readable DHCP message type name from
// the decoded pairs ("Discover", "Solicit", etc.), or "" when none is
// present.
func messageTypeName(pairs []attrs.Pair) string {
	for _, p := range pairs {
		if p.Attr == nil {
			continue
		}
		if p.Attr.Name != "Message-Type" && p.Attr.Name != "Packet-Type" {
			continue
		}
		if name, ok := p.Attr.EnumByValue[p.Value.Uint]; ok {
			return name
		}
	}
	return ""
}

// ipString picks the IPv4 short form when possible. net.IP.String already
// does this but we use it through a helper so callers don't need to
// import net.
func ipString(ip interface{ String() string }) string {
	if ip == nil {
		return "?"
	}
	return ip.String()
}

// (unused import guard) keep encoding/binary in scope — pcap headers
// could be inspected here in future verbose modes.
var _ = binary.BigEndian
