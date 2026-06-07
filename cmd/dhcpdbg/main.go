// Command dhcpdbg: craft, send, and inspect DHCPv4 / DHCPv6 packets using
// FreeRADIUS attribute notation. See README.md and dhcpdbg-prompt.md for
// scope and usage.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ludomikula/dhcpdbg/internal/cli"
	"github.com/ludomikula/dhcpdbg/internal/sock"
)

// stringSlice is a flag.Value that accumulates repeated --dict values.
type stringSlice []string

func (s *stringSlice) String() string     { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error { *s = append(*s, v); return nil }

func main() {
	var (
		v4          = flag.Bool("4", false, "use DHCPv4")
		v6          = flag.Bool("6", false, "use DHCPv6")
		msgType     = flag.String("t", "", "message type (e.g. discover, solicit)")
		server      = flag.String("s", "", "target server [host[:port]]")
		iface       = flag.String("i", "", "egress interface (required for raw/listen)")
		sockModeS   = flag.String("socket", "udp", "socket backend: udp|raw")
		modeS       = flag.String("mode", "request", "operating mode: request|listen")
		retries     = flag.Int("r", 2, "retries on timeout")
		timeoutS    = flag.String("T", "3s", "reply timeout (e.g. 2s, 500ms)")
		inputPath   = flag.String("f", "", "attribute-list input file (default stdin)")
		x           = flag.Bool("x", false, "verbose output (-xx for hex dump)")
		xx          = flag.Bool("xx", false, "very verbose (hex dump)")
		dictReplace = flag.Bool("dict-replace", false, "skip embedded dictionaries; only load --dict paths")
		decOpt43    = flag.String("decode-option-43", "", "vendor name (under Decoded-Option-43) used to parse option 43 payloads")
		listDicts   = flag.Bool("list-dicts", false, "list every loaded dictionary file and exit")
		printDict   = flag.Bool("print-dict", false, "print the loaded dictionary tree and exit")
		formatS     = flag.String("format", "text", "info output format: text|json")
		showHelp    = flag.Bool("h", false, "show this help")
	)
	var dictPaths stringSlice
	var infoVendors stringSlice
	flag.Var(&dictPaths, "dict", "extra FreeRADIUS dictionary file or directory (repeatable)")
	flag.Var(&infoVendors, "vendor", "filter --print-dict to the named vendor (repeatable)")
	flag.Usage = usage
	flag.Parse()

	if *showHelp || (!*v4 && !*v6) {
		usage()
		if *showHelp {
			os.Exit(0)
		}
		os.Exit(2)
	}
	if *v4 && *v6 {
		fail("-4 and -6 are mutually exclusive")
	}

	family := cli.V4
	if *v6 {
		family = cli.V6
	}

	// Info mode: --list-dicts and --print-dict both bypass the socket and
	// rendering input file. --vendor without one of the dump flags implies
	// --print-dict.
	wantInfo := *listDicts || *printDict || len(infoVendors) > 0
	if wantInfo {
		// Reject combinations that don't make sense — info mode is
		// self-contained and mixes badly with packet I/O.
		if *msgType != "" || *iface != "" || *server != "" || *inputPath != "" {
			fail("info flags (--list-dicts, --print-dict, --vendor) cannot be combined with -t/-i/-s/-f")
		}
		if *modeS != "request" {
			fail("info flags cannot be combined with --mode=%s", *modeS)
		}
		var im cli.InfoMode
		switch {
		case *listDicts && *printDict:
			fail("--list-dicts and --print-dict are mutually exclusive")
		case *listDicts:
			im = cli.InfoListDicts
		default:
			im = cli.InfoPrintDict
		}
		var asJSON bool
		switch *formatS {
		case "text":
			asJSON = false
		case "json":
			asJSON = true
		default:
			fail("unknown --format=%q (want text|json)", *formatS)
		}
		rc := cli.Run(cli.Options{
			Family:      family,
			Mode:        cli.ModeInfo,
			InfoMode:    im,
			InfoVendors: []string(infoVendors),
			InfoJSON:    asJSON,
			DictPaths:   []string(dictPaths),
			DictReplace: *dictReplace,
		})
		os.Exit(rc)
	}

	timeout, err := time.ParseDuration(*timeoutS)
	if err != nil {
		fail("bad -T %q: %v", *timeoutS, err)
	}

	var sm sock.Mode
	switch *sockModeS {
	case "udp":
		sm = sock.ModeUDP
	case "raw":
		sm = sock.ModeRaw
	default:
		fail("unknown --socket=%q (want udp|raw)", *sockModeS)
	}

	var mode cli.Mode
	switch *modeS {
	case "request":
		mode = cli.ModeRequest
	case "listen":
		mode = cli.ModeListen
	default:
		fail("unknown --mode=%q (want request|listen)", *modeS)
	}

	if sm == sock.ModeRaw && *iface == "" {
		fail("--socket=raw requires -i <iface>")
	}
	if mode == cli.ModeListen && *iface == "" && sm == sock.ModeRaw {
		fail("--mode=listen with --socket=raw requires -i <iface>")
	}

	verbosity := 0
	if *x {
		verbosity = 1
	}
	if *xx {
		verbosity = 2
	}

	rc := cli.Run(cli.Options{
		Family:         family,
		Mode:           mode,
		SockMode:       sm,
		MsgTypeName:    *msgType,
		Server:         *server,
		Iface:          *iface,
		Retries:        *retries,
		Timeout:        timeout,
		InputPath:      *inputPath,
		Verbosity:      verbosity,
		DictPaths:      []string(dictPaths),
		DictReplace:    *dictReplace,
		DecodeOption43: *decOpt43,
	})
	os.Exit(rc)
}

func usage() {
	fmt.Fprintf(os.Stderr, `dhcpdbg — craft, send, and inspect DHCPv4/DHCPv6 packets

Usage:
  dhcpdbg (-4|-6) [-t TYPE] [-s SERVER[:PORT]] [-i IFACE]
          [--socket udp|raw] [--mode request|listen]
          [-r RETRIES] [-T TIMEOUT] [-f FILE] [-x | -xx]
          [--dict PATH ...] [--dict-replace]
          [--decode-option-43 VENDOR]
  dhcpdbg (-4|-6) (--list-dicts | --print-dict [--vendor NAME ...])
          [--dict PATH ...] [--dict-replace] [--format text|json]

Examples:
  dhcpdbg -4 -t discover -i eth0 --socket=raw -s 255.255.255.255 < attrs.txt
  dhcpdbg -6 -t solicit -i eth0
  dhcpdbg -4 --mode=listen -i eth0
  dhcpdbg -4 --list-dicts
  dhcpdbg -4 --print-dict --vendor=ADSL-Forum
  dhcpdbg -4 --print-dict --dict /etc/dhcpdbg/dictionary.acme --format=json

Input format (one attribute per line, blank lines separate packets):
  Hostname = "lab-host"
  Parameter-Request-List = Subnet-Mask
  Parameter-Request-List = Router-Address

Exit codes: 0 success, 2 parse/encode error, 3 socket error, 4 timeout,
5 NAK or DHCPv6 non-Success status.
`)
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "dhcpdbg: "+format+"\n", args...)
	os.Exit(2)
}
