# dhcpdbg

A single-binary Go CLI for crafting, sending, and inspecting DHCPv4 and DHCPv6
packets, using FreeRADIUS attribute notation as the on-the-wire syntax.

`dhcpdbg` is built for the same workflow as `radclient` / `dhcpclient`: write
a packet as a list of `Attribute = value` lines, send it on the network,
read the reply back as another list of `Attribute = value` lines. It speaks
both protocol families with the same input and output format, so a single
shell pipeline can construct a DHCPv4 DISCOVER one moment and a DHCPv6
SOLICIT the next.

## Highlights

- **Both protocol families are first-class** — DHCPv4 (RFC 2131/2132) and
  DHCPv6 (RFC 8415) are selected per invocation via `-4` / `-6`.
- **FreeRADIUS dictionaries are embedded at compile time** via `//go:embed`
  — the binary carries every standard and vendor attribute it understands
  and reads no external files at runtime.
- **Two socket backends**: plain UDP (default) for unicast renew / inform
  workflows and for talking to a relay, or AF_PACKET raw (Linux) when the
  source address must be `0.0.0.0` (DHCPv4) or a link-local (DHCPv6) before
  a lease exists.
- **Two operating modes**: `request` sends a packet and waits for the
  matching reply; `listen` binds the socket and prints every DHCP packet it
  observes until interrupted.
- **Round-trippable output** — replies are printed in the exact attribute
  notation the encoder accepts as input, so capture and replay are one
  pipeline.
- **Single static binary, ~4.5 MB**, distroless image, no host runtime
  dependencies.

## How it works

The tool parses its input into typed `(name, value)` pairs using the
embedded FreeRADIUS dictionaries, then walks the resulting list to build
the wire packet:

- **DHCPv4** writes a 236-octet BOOTP header (op, htype, hlen, hops, xid,
  secs, flags, ciaddr, yiaddr, siaddr, giaddr, chaddr, sname, file), a
  4-octet magic cookie, an ordered run of TLV options sorted by code, the
  End option, and trailing pad to 300 octets. Repeated entries of the same
  option code aggregate into a single payload (RFC 3396).
- **DHCPv6** writes a 4-octet header (message type + 24-bit transaction
  ID), then a sequence of `code(2) + len(2) + value` options. Array-typed
  attributes (such as `Option-Request`) aggregate their entries into a
  single option payload (RFC 8415 §21.7).

BOOTP-header fields and DHCPv6 message-type / transaction-id are surfaced
as pseudo-attributes in the FreeRADIUS "internal" namespace, so users can
override them from input just like any other attribute and the decoder
prints them on the way back out.

## Build

The build runs entirely inside Docker — the only host requirement is
Docker. A `golang:1.22-alpine` stage produces a fully static binary; the
final stage is `gcr.io/distroless/static:nonroot` and contains nothing but
the executable.

### One-line build

```sh
./scripts/build.sh
```

This builds the image, extracts the binary, and drops `./dhcpdbg` into the
project root.

### Manual build

```sh
# Build the final distroless image:
docker build -t dhcpdbg:local .

# Or pull the binary out into the host CWD:
docker build -t dhcpdbg:build --target build .
cid=$(docker create dhcpdbg:build)
docker cp "${cid}:/out/dhcpdbg" ./dhcpdbg
docker rm "${cid}"
```

### Running

You can run the binary directly:

```sh
./dhcpdbg -h
```

Or invoke it through the container (useful for hosts that don't ship glibc
compatible with the build):

```sh
docker run --rm -i --network host dhcpdbg:local -4 -t discover -i eth0 < attrs.txt
```

`--network host` is required when you want the container to see real
interfaces; raw mode additionally needs `--cap-add NET_RAW`.

## CLI synopsis

```
dhcpdbg (-4|-6) [-t TYPE] [-s SERVER[:PORT]] [-i IFACE]
        [--socket udp|raw] [--mode request|listen]
        [-r RETRIES] [-T TIMEOUT] [-f FILE] [-x | -xx]
```

| Flag | Meaning |
|------|---------|
| `-4` / `-6`        | Select protocol family (mutually exclusive, one required). |
| `-t TYPE`          | Message type name (case-insensitive). Resolved against the dictionary's `Packet-Type` enum (`discover`, `solicit`, `request`, `renew`, `release`, `inform`, `decline`, `rebind`, `information-request`, ...). Ignored if the input file already sets `Packet-Type` or DHCPv4 `Message-Type`. |
| `-s HOST[:PORT]`   | Target server. Defaults: `255.255.255.255:67` for DHCPv4, `[ff02::1:2]:547` for DHCPv6 (all-DHCP-relay-agents-and-servers). |
| `-i IFACE`         | Egress interface. Required for `--socket=raw` and recommended for `--mode=listen`. For DHCPv6 it also selects the multicast egress interface. |
| `--socket=udp|raw` | Socket backend. `udp` (default) uses a regular bound UDP socket. `raw` uses AF_PACKET DGRAM on Linux and lets you send from `0.0.0.0` before a lease exists. |
| `--mode=request|listen` | `request` (default) sends a packet, waits for the matching reply, prints it, exits. `listen` binds and prints every DHCP packet observed on the socket until SIGINT. |
| `-r RETRIES`       | Retries on reply timeout. Default `2`. |
| `-T TIMEOUT`       | Reply timeout. Accepts Go duration syntax (`2s`, `500ms`, `1m30s`). Default `3s`. |
| `-f FILE`          | Read the attribute list from `FILE`. Defaults to stdin. Ignored in listen mode. |
| `-x`               | Verbose: trace each send / receive on stderr. |
| `-xx`              | Very verbose: also dump the raw packet hex. |
| `-h`               | Show help. |

## Input format

The input is a list of `Attribute = value` lines, one per line. Blank lines
separate records (request mode reads the first record; the format can also
carry multiple records for future scripted use). Lines beginning with `#`
are comments.

```text
# A minimal DHCPv4 DISCOVER preamble.
Client-Hardware-Address = 02:00:00:00:00:01
Hostname = "lab-discover"
Parameter-Request-List = Subnet-Mask
Parameter-Request-List = Router-Address
Parameter-Request-List = Domain-Name-Server
```

Value syntax is type-aware and follows FreeRADIUS conventions:

| Type             | Example                                              |
|------------------|------------------------------------------------------|
| `uint8/16/32/64` | `42`, `0xff`, `Discover` (enum name)                 |
| `bool`           | `yes`, `no`, `true`, `false`, `1`, `0`               |
| `string`         | `"lab-host"` (double-quoted) or bare                 |
| `octets`         | `0x00010203` or a bare string (UTF-8 bytes)          |
| `ipaddr` (v4)    | `10.0.0.1`                                           |
| `ipv6addr`       | `fe80::1`, `2001:db8::1`                             |
| `ether`          | `02:00:00:00:00:01` or `0200.0000.0001`              |
| `ipv4prefix`     | `10.0.0.0/24`                                        |
| `ipv6prefix`     | `2001:db8::/64`                                      |
| `attribute`      | The name of another attribute (`Subnet-Mask`)        |

When the dictionary marks an attribute as `array` (DHCPv4
`Parameter-Request-List`, DHCPv6 `Option-Request`, `Domain-Name-Server`,
etc.), each repeated occurrence on its own line appends another element to
the same option's payload.

Complex DHCPv6 structures (`Client-ID`, `Server-ID`, `IA-NA`, `IA-Addr`,
`Vendor-Opts`, ...) are accepted as opaque hex blobs. Build the encoded
form directly:

```text
Client-ID = 0x00030001020000000001
IA-NA = 0x0000000100000e1000001518
```

## Output format

Replies (request mode) and observed packets (listen mode) are printed in
the same attribute notation accepted as input — output is round-trippable.
Header fields appear first (Opcode, Transaction-Id, Client-IP-Address,
...), followed by options in the order they appear on the wire. Listen
mode prefixes each record with `# from <addr>` so multiple replies are
distinguishable.

Diagnostic output (`-x`, `-xx`) goes to stderr; the decoded packet always
goes to stdout, so piping the output back into a follow-up `dhcpdbg`
invocation works without filtering.

## Exit codes

| Code | Meaning                                              |
|------|------------------------------------------------------|
| 0    | Success (or listen mode exited cleanly on SIGINT).   |
| 2    | Input parse error, encode error, or bad flag combo.  |
| 3    | Socket-level error (bind, send, receive).            |
| 4    | Reply timeout (all retries exhausted).               |
| 5    | DHCPv4 NAK received, or DHCPv6 reply carried a Status-Code option with a non-Success value. |

## Examples

### DHCPv4

**Vanilla DISCOVER from an unconfigured interface (raw socket, broadcast):**

```sh
sudo ./dhcpdbg -4 -t discover -i eth0 --socket=raw -s 255.255.255.255 <<EOF
Client-Hardware-Address = 02:00:00:00:00:01
Hostname = "lab-discover"
Parameter-Request-List = Subnet-Mask
Parameter-Request-List = Router-Address
Parameter-Request-List = Domain-Name-Server
Parameter-Request-List = Domain-Name
EOF
```

**DISCOVER with a Client-Identifier and Vendor-Class-Identifier:**

```sh
sudo ./dhcpdbg -4 -t discover -i eth0 --socket=raw -s 255.255.255.255 <<EOF
Client-Hardware-Address = 02:00:00:00:00:42
Client-Identifier = 0x01020000000042
Vendor-Class-Identifier = "MSFT 5.0"
Hostname = "winbox-lab"
Parameter-Request-List = Subnet-Mask
Parameter-Request-List = Router-Address
Parameter-Request-List = Domain-Name-Server
Parameter-Request-List = NETBIOS-Name-Servers
Parameter-Request-List = NETBIOS-Node-Type
EOF
```

**REQUEST a specific offered address (after seeing an OFFER):**

```sh
sudo ./dhcpdbg -4 -t request -i eth0 --socket=raw -s 255.255.255.255 <<EOF
Client-Hardware-Address = 02:00:00:00:00:01
Requested-IP-Address = 10.0.0.42
Server-Identifier = 10.0.0.1
Parameter-Request-List = Subnet-Mask
Parameter-Request-List = Router-Address
EOF
```

**RELEASE an active lease (unicast to the server, source IP is the leased
address — use plain UDP, not raw):**

```sh
sudo ./dhcpdbg -4 -t release -s 10.0.0.1 <<EOF
Client-Hardware-Address = 02:00:00:00:00:01
Client-IP-Address = 10.0.0.42
Server-Identifier = 10.0.0.1
EOF
```

RELEASE is one-way; `dhcpdbg` notices and does not wait for a reply.

**INFORM (we already have an IP, we just want config options):**

```sh
sudo ./dhcpdbg -4 -t inform -s 10.0.0.1 <<EOF
Client-Hardware-Address = 02:00:00:00:00:01
Client-IP-Address = 10.0.0.42
Parameter-Request-List = Domain-Name-Server
Parameter-Request-List = NTP-Servers
Parameter-Request-List = Domain-Name
EOF
```

**DECLINE (refuse a previously-offered IP — e.g. ARP collision detected):**

```sh
sudo ./dhcpdbg -4 -t decline -i eth0 --socket=raw -s 255.255.255.255 <<EOF
Client-Hardware-Address = 02:00:00:00:00:01
Requested-IP-Address = 10.0.0.42
Server-Identifier = 10.0.0.1
Message = "address conflict detected"
EOF
```

**Reproducible packets — pin the transaction id and hostname:**

```sh
./dhcpdbg -4 -t discover -s 10.0.0.1 -xx <<EOF
Client-Hardware-Address = 02:00:00:00:00:01
Transaction-Id = 0xdeadbeef
Hostname = "fixed"
Number-of-Seconds = 0
Parameter-Request-List = Subnet-Mask
EOF
```

`-xx` prints the encoded packet as a hex dump on stderr; with a pinned
transaction id, byte-for-byte comparisons against a reference encoder are
straightforward.

**Listen for every DHCPv4 packet on an interface:**

```sh
sudo ./dhcpdbg -4 --mode=listen -i eth0
```

Each captured packet is printed in attribute notation with a `# from <ip>`
prefix. Ctrl-C exits cleanly.

**Capture, edit, and replay a DHCP exchange:**

```sh
sudo ./dhcpdbg -4 --mode=listen -i eth0 > capture.txt
# ... edit capture.txt, change Requested-IP-Address, ...
./dhcpdbg -4 -t request -s 10.0.0.1 -f capture.txt
```

### DHCPv6

**Vanilla SOLICIT (multicast to all-DHCP-relays-and-servers):**

```sh
sudo ./dhcpdbg -6 -t solicit -i eth0 <<EOF
Client-ID = 0x00030001020000000001
IA-NA = 0x0000000100000e1000001518
Option-Request = DNS-Servers
Option-Request = Domain-List
EOF
```

Defaults: target `[ff02::1:2]:547`, client source port `546`. The
`Client-ID` octets above encode a DUID-LLT (type 3, hwtype 1=Ethernet,
MAC `02:00:00:00:00:01`). `IA-NA` carries IAID `0x00000001`, T1 `3600`,
T2 `5400` and no nested options.

**SOLICIT with Rapid Commit:**

```sh
sudo ./dhcpdbg -6 -t solicit -i eth0 <<EOF
Client-ID = 0x00030001020000000001
IA-NA = 0x0000000100000e1000001518
Rapid-Commit = yes
Option-Request = DNS-Servers
EOF
```

**REQUEST after ADVERTISE (echo back the Server-ID from the reply):**

```sh
sudo ./dhcpdbg -6 -t request -i eth0 <<EOF
Client-ID = 0x00030001020000000001
Server-ID = 0x0001000123456789abcdef0001
IA-NA = 0x0000000100000e1000001518
Option-Request = DNS-Servers
Option-Request = Domain-List
EOF
```

**RENEW (unicast to the server that issued the lease):**

```sh
sudo ./dhcpdbg -6 -t renew -s 2001:db8::1 <<EOF
Client-ID = 0x00030001020000000001
Server-ID = 0x0001000123456789abcdef0001
IA-NA = 0x0000000100000e1000001518
EOF
```

**REBIND (multicast — no Server-ID, any server may answer):**

```sh
sudo ./dhcpdbg -6 -t rebind -i eth0 <<EOF
Client-ID = 0x00030001020000000001
IA-NA = 0x0000000100000e1000001518
EOF
```

**RELEASE the lease back to the server:**

```sh
sudo ./dhcpdbg -6 -t release -s 2001:db8::1 <<EOF
Client-ID = 0x00030001020000000001
Server-ID = 0x0001000123456789abcdef0001
IA-NA = 0x0000000100000e1000001518
EOF
```

**INFORMATION-REQUEST (stateless config, no IA):**

```sh
sudo ./dhcpdbg -6 -t information-request -i eth0 <<EOF
Client-ID = 0x00030001020000000001
Option-Request = DNS-Servers
Option-Request = Domain-List
Option-Request = SNTP-Servers
EOF
```

**Pin the 24-bit DHCPv6 transaction id for reproducible packets:**

```sh
./dhcpdbg -6 -t solicit -s '[::1]:5470' -xx <<EOF
Transaction-ID = 0xabcdef
Client-ID = 0x00030001020000000001
IA-NA = 0x0000000100000e1000001518
EOF
```

Note `Transaction-ID` is an octets-typed pseudo-attribute on the DHCPv6
internal namespace; it takes exactly three octets.

**Listen for every DHCPv6 packet (both client-port 546 traffic and
multicast):**

```sh
sudo ./dhcpdbg -6 --mode=listen -i eth0
```

### Mixed / advanced

**Force a specific Transaction-Id and inspect the encoded bytes without
sending a real exchange (point at a closed port and let the timeout fire):**

```sh
./dhcpdbg -4 -t discover -s 127.0.0.1:9999 -T 100ms -r 0 -xx <<EOF
Client-Hardware-Address = 02:00:00:00:00:01
Transaction-Id = 0xcafef00d
EOF
```

The encoded packet appears on stderr immediately after the send; the
"timeout" exit (4) is expected because no server is listening.

**Read packet attrs from a file instead of stdin:**

```sh
cat > /tmp/inform.attrs <<EOF
Client-Hardware-Address = 02:00:00:00:00:01
Client-IP-Address = 10.0.0.42
Parameter-Request-List = Domain-Name-Server
Parameter-Request-List = NTP-Servers
EOF
sudo ./dhcpdbg -4 -t inform -s 10.0.0.1 -f /tmp/inform.attrs
```

**Quick-and-dirty server validation — repeat a DISCOVER three times:**

```sh
for i in 1 2 3; do
  sudo ./dhcpdbg -4 -t discover -i eth0 --socket=raw -s 255.255.255.255 \
       -T 1s -r 0 <<EOF || echo "discover $i: no reply"
Client-Hardware-Address = 02:00:00:00:00:0${i}
EOF
done
```

**Test that an invalid attribute name produces a clear error:**

```sh
./dhcpdbg -4 -t discover -s 10.0.0.1 <<EOF
Not-A-Real-Attribute = "boom"
EOF
# dhcpdbg: line 1: unknown attribute "Not-A-Real-Attribute"
# Exit code: 2
```

**Run inside the prebuilt container (no binary extracted to host):**

```sh
docker run --rm -i --network host --cap-add NET_RAW dhcpdbg:local \
  -4 -t discover -i eth0 --socket=raw -s 255.255.255.255 <<EOF
Client-Hardware-Address = 02:00:00:00:00:01
Hostname = "lab-host"
EOF
```

## Privileges

The standard DHCP client ports (UDP/68 for DHCPv4, UDP/546 for DHCPv6) are
below 1024 and require either root, `CAP_NET_BIND_SERVICE`, or a sysctl /
sysctl-equivalent override on Linux. Raw mode additionally requires
`CAP_NET_RAW` (or root). `dhcpdbg` checks `/proc/self/status` for these
capabilities and fails fast with a clear message when they are missing,
rather than letting the kernel return a generic `EPERM` from the bind /
socket call.

When running from the container, pass `--cap-add NET_BIND_SERVICE` (and
`NET_RAW` for raw mode) to inherit the host's capability mask.

## Limitations

- **Structured DHCPv6 attributes** (`Client-ID`, `Server-ID`, `IA-NA`,
  `IA-Addr`, `IA-PD`, `IA-Prefix`, `Vendor-Opts`, `Authentication`) are
  accepted and printed as opaque hex blobs. Construct them per the
  relevant RFC and pass them directly. A future revision can replace this
  with field-by-field encoding once the v4-dictionary struct grammar is
  fully modeled.
- **Vendor sub-options** (DHCPv4 option 43, DHCPv6 option 17) likewise
  pass through as opaque octets.
- **Raw mode is Linux-only.** Builds on other platforms compile the
  stubbed implementation, which fails at runtime with an explanatory
  message. UDP mode works everywhere.
- The default ports (`68`, `546`) are hardcoded; running as a non-root
  user against a server on a non-standard port currently still requires
  privileges because the source port stays on the canonical DHCP client
  port.
