package pcap

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

// pcapng on-disk format (https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-04.html):
//
//   Every block:
//     Block Type     uint32
//     Block Length   uint32   (includes header + body + trailing length)
//     Body           ...
//     Block Length   uint32   (same value as above, repeated)
//
//   Section Header Block (0x0A0D0D0A):
//     Byte-Order Magic  uint32  - 0x1A2B3C4D in the section's byte order
//     Major Version     uint16
//     Minor Version     uint16
//     Section Length    int64
//     Options...
//
//   Interface Description Block (0x00000001):
//     LinkType  uint16
//     Reserved  uint16
//     Snaplen   uint32
//     Options...   (we honour `if_tsresol` for sub-second resolution)
//
//   Enhanced Packet Block (0x00000006):
//     Interface ID    uint32
//     Timestamp High  uint32
//     Timestamp Low   uint32
//     Captured Len    uint32
//     Original Len    uint32
//     Packet Data     ...
//     Options...
//
//   Simple Packet Block (0x00000003):
//     Original Len    uint32
//     Packet Data     ...   (length = block-length - 16)
//
// We honour SHB / IDB / EPB / SPB and skip any other block by jumping
// ahead by its declared length.
const (
	blockSHB = 0x0A0D0D0A
	blockIDB = 0x00000001
	blockEPB = 0x00000006
	blockSPB = 0x00000003
)

// pcapngInterface holds the per-IDB state we need to decode an EPB/SPB.
// pcapng allows mixing interfaces in one file (one Wi-Fi + one wired,
// say) — each packet block references its interface by index.
type pcapngInterface struct {
	linkType int
	snaplen  uint32
	tsresol  uint32 // ticks per second (default 1e6)
}

type pcapngReader struct {
	r          io.Reader
	bo         binary.ByteOrder
	interfaces []pcapngInterface
}

func newPcapngReader(r io.Reader) (Reader, error) {
	// First block MUST be a Section Header Block.
	pr := &pcapngReader{r: r}
	if err := pr.readSHB(); err != nil {
		return nil, fmt.Errorf("pcapng: %w", err)
	}
	return pr, nil
}

// readSHB consumes the next Section Header Block, establishing byte
// order and resetting the interface table for the new section.
func (p *pcapngReader) readSHB() error {
	// Read block type + block length using little-endian first, then
	// detect order from the SHB's byte-order magic field.
	hdr := make([]byte, 12)
	if _, err := io.ReadFull(p.r, hdr); err != nil {
		return fmt.Errorf("SHB header: %w", err)
	}
	leType := binary.LittleEndian.Uint32(hdr[0:4])
	if leType != blockSHB {
		// Big-endian peer that wrote a big-endian SHB? Unlikely (the
		// block type is byte-order invariant), but check anyway.
		beType := binary.BigEndian.Uint32(hdr[0:4])
		if beType != blockSHB {
			return fmt.Errorf("first block isn't SHB (got %#08x)", leType)
		}
	}
	leLen := binary.LittleEndian.Uint32(hdr[4:8])
	bom := hdr[8:12]
	var bo binary.ByteOrder
	switch binary.LittleEndian.Uint32(bom) {
	case 0x1A2B3C4D:
		bo = binary.LittleEndian
	default:
		switch binary.BigEndian.Uint32(bom) {
		case 0x1A2B3C4D:
			bo = binary.BigEndian
		default:
			return fmt.Errorf("SHB has bad byte-order magic %x", bom)
		}
	}
	p.bo = bo
	blkLen := bo.Uint32(hdr[4:8])
	// Sanity check: byte-order magic should match either LE-read or
	// the magnitude we just resolved.
	_ = leLen
	if blkLen < 12 || blkLen%4 != 0 {
		return fmt.Errorf("SHB bad length %d", blkLen)
	}
	// We've read 12 bytes of the block already. Skip the rest of the
	// SHB body (version + section length + options + trailing length).
	rest := int64(blkLen) - 12
	if _, err := io.CopyN(io.Discard, p.r, rest); err != nil {
		return fmt.Errorf("SHB body: %w", err)
	}
	// New section -> fresh interface table.
	p.interfaces = nil
	return nil
}

// Next reads blocks until it produces a DHCP Frame, encounters EOF, or
// hits a structural error. IDB blocks update p.interfaces; SPB / EPB
// blocks become Frames; SHB blocks start a new section (reset
// interfaces).
func (p *pcapngReader) Next() (*Frame, error) {
	for {
		// Block header: type (4) + length (4).
		hdr := make([]byte, 8)
		if _, err := io.ReadFull(p.r, hdr); err != nil {
			return nil, err
		}
		btype := p.bo.Uint32(hdr[0:4])
		blen := p.bo.Uint32(hdr[4:8])
		if blen < 12 || blen%4 != 0 {
			return nil, fmt.Errorf("pcapng: bad block length %d", blen)
		}
		// Remaining body bytes (block length includes the 8 header
		// bytes we just read + the 4-byte trailing length).
		bodyLen := int(blen) - 12
		body := make([]byte, bodyLen)
		if _, err := io.ReadFull(p.r, body); err != nil {
			return nil, fmt.Errorf("pcapng: short block body: %w", err)
		}
		// Trailing length.
		trail := make([]byte, 4)
		if _, err := io.ReadFull(p.r, trail); err != nil {
			return nil, fmt.Errorf("pcapng: short block trailer: %w", err)
		}
		switch btype {
		case blockSHB:
			// Mid-stream new section: re-init from this SHB.
			if err := p.absorbSHB(body); err != nil {
				return nil, err
			}
		case blockIDB:
			if err := p.absorbIDB(body); err != nil {
				return nil, err
			}
		case blockEPB:
			frame, err := p.frameFromEPB(body)
			if err == errSkip {
				continue
			}
			if err != nil {
				return nil, err
			}
			return frame, nil
		case blockSPB:
			frame, err := p.frameFromSPB(body)
			if err == errSkip {
				continue
			}
			if err != nil {
				return nil, err
			}
			return frame, nil
		default:
			// Unknown block — skip silently. The block-length field
			// makes this safe even for blocks we've never seen.
		}
	}
}

// absorbSHB resets the section state from the body of a new SHB. Body
// excludes the 8 header bytes and the 4 trailing length bytes.
func (p *pcapngReader) absorbSHB(body []byte) error {
	if len(body) < 12 {
		return fmt.Errorf("SHB body too short")
	}
	// Verify byte-order magic against current bo.
	if p.bo.Uint32(body[0:4]) != 0x1A2B3C4D {
		// Byte-order switched mid-file; rare but legal.
		switch {
		case binary.LittleEndian.Uint32(body[0:4]) == 0x1A2B3C4D:
			p.bo = binary.LittleEndian
		case binary.BigEndian.Uint32(body[0:4]) == 0x1A2B3C4D:
			p.bo = binary.BigEndian
		default:
			return fmt.Errorf("SHB bad byte-order magic")
		}
	}
	p.interfaces = nil
	return nil
}

func (p *pcapngReader) absorbIDB(body []byte) error {
	if len(body) < 8 {
		return fmt.Errorf("IDB body too short")
	}
	iface := pcapngInterface{
		linkType: int(p.bo.Uint16(body[0:2])),
		snaplen:  p.bo.Uint32(body[4:8]),
		tsresol:  1_000_000, // default microsecond
	}
	// Walk options for `if_tsresol` (code 9). Options follow the
	// fixed 8-byte head: code (uint16) + length (uint16) + value + pad.
	off := 8
	for off+4 <= len(body) {
		code := p.bo.Uint16(body[off : off+2])
		ln := int(p.bo.Uint16(body[off+2 : off+4]))
		off += 4
		if code == 0 {
			break // opt_endofopt
		}
		if off+ln > len(body) {
			break
		}
		if code == 9 && ln >= 1 {
			// tsresol: if MSB is 0, value is power-of-10 exponent;
			// if MSB is 1, it's power-of-2. Default exponent 6 (us).
			raw := body[off]
			if raw&0x80 == 0 {
				iface.tsresol = pow10(int(raw))
			} else {
				iface.tsresol = 1 << (raw & 0x7f)
			}
		}
		// Align to 4-byte boundary.
		padded := (ln + 3) &^ 3
		off += padded
	}
	p.interfaces = append(p.interfaces, iface)
	return nil
}

func (p *pcapngReader) frameFromEPB(body []byte) (*Frame, error) {
	if len(body) < 20 {
		return nil, fmt.Errorf("EPB body too short")
	}
	iface := p.bo.Uint32(body[0:4])
	tsHi := p.bo.Uint32(body[4:8])
	tsLo := p.bo.Uint32(body[8:12])
	caplen := p.bo.Uint32(body[12:16])
	origlen := p.bo.Uint32(body[16:20])
	if int(iface) >= len(p.interfaces) {
		return nil, fmt.Errorf("EPB references unknown interface %d", iface)
	}
	info := p.interfaces[iface]
	if 20+int(caplen) > len(body) {
		return nil, fmt.Errorf("EPB caplen %d overruns body %d", caplen, len(body)-20)
	}
	pkt := body[20 : 20+caplen]
	ts := pcapngTimestamp(tsHi, tsLo, info.tsresol)
	return frameFromBytes(info.linkType, pkt, int(origlen), ts)
}

func (p *pcapngReader) frameFromSPB(body []byte) (*Frame, error) {
	// SPB has no interface ID — interface 0 is implied. Body: origlen
	// (uint32) followed by packet data. caplen = body-len - 4.
	if len(body) < 4 {
		return nil, fmt.Errorf("SPB body too short")
	}
	origlen := p.bo.Uint32(body[0:4])
	pkt := body[4:]
	if len(p.interfaces) == 0 {
		return nil, fmt.Errorf("SPB before any IDB")
	}
	info := p.interfaces[0]
	// SPB has no timestamp; use zero.
	return frameFromBytes(info.linkType, pkt, int(origlen), time.Time{})
}

// pcapngTimestamp combines the (hi, lo) 64-bit tick count with the
// interface's resolution (ticks/second) into a UTC time.Time.
func pcapngTimestamp(hi, lo, resol uint32) time.Time {
	if resol == 0 {
		resol = 1_000_000
	}
	ticks := uint64(hi)<<32 | uint64(lo)
	sec := int64(ticks / uint64(resol))
	rem := ticks % uint64(resol)
	// Promote remainder to nanoseconds.
	nsec := int64(rem) * int64(1_000_000_000/uint64(resol))
	return time.Unix(sec, nsec).UTC()
}

func pow10(n int) uint32 {
	out := uint32(1)
	for i := 0; i < n; i++ {
		out *= 10
	}
	return out
}
