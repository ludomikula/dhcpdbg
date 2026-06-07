package pcap

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

// Classic libpcap on-disk format (RFC-style spec at
// https://www.tcpdump.org/pcap/pcap.html):
//
//   Global header (24 bytes):
//     magic_number  uint32   - 0xa1b2c3d4 (native order) or 0xa1b23c4d (nanos)
//     version_major uint16   - 2
//     version_minor uint16   - 4
//     thiszone      int32    - GMT offset, usually 0
//     sigfigs       uint32   - usually 0
//     snaplen       uint32   - max bytes captured per packet
//     network       uint32   - libpcap LINKTYPE_*
//
//   Per-packet record (16 bytes + caplen bytes):
//     ts_sec        uint32
//     ts_usec       uint32   - microseconds (or nanos when magic says so)
//     caplen        uint32   - bytes captured
//     origlen       uint32   - bytes on the wire
//
// All multi-byte fields use the byte order implied by the magic.
type classicReader struct {
	r        io.Reader
	bo       binary.ByteOrder
	linkType int
	snaplen  uint32
	// nanos is true when the magic was 0xa1b23c4d, meaning ts_usec is
	// actually nanoseconds.
	nanos bool
}

func newClassicReader(r io.Reader) (Reader, error) {
	hdr := make([]byte, 24)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, fmt.Errorf("classic pcap: short global header: %w", err)
	}
	// Determine byte order from the magic.
	leMagic := binary.LittleEndian.Uint32(hdr[0:4])
	beMagic := binary.BigEndian.Uint32(hdr[0:4])
	var bo binary.ByteOrder
	var nanos bool
	switch {
	case leMagic == 0xa1b2c3d4:
		bo, nanos = binary.LittleEndian, false
	case leMagic == 0xa1b23c4d:
		bo, nanos = binary.LittleEndian, true
	case beMagic == 0xa1b2c3d4:
		bo, nanos = binary.BigEndian, false
	case beMagic == 0xa1b23c4d:
		bo, nanos = binary.BigEndian, true
	case leMagic == 0xd4c3b2a1:
		// Byte-swapped form: file was written by a big-endian host but
		// our reader is treating it as little-endian. The fields are
		// in the OPPOSITE order to ours.
		bo, nanos = binary.BigEndian, false
	case beMagic == 0xd4c3b2a1:
		bo, nanos = binary.LittleEndian, false
	default:
		return nil, fmt.Errorf("classic pcap: bad magic %#x", leMagic)
	}
	return &classicReader{
		r:        r,
		bo:       bo,
		linkType: int(bo.Uint32(hdr[20:24])),
		snaplen:  bo.Uint32(hdr[16:20]),
		nanos:    nanos,
	}, nil
}

// Next reads packet records until one is a DHCP UDP datagram (or EOF).
// Frame-decode errors (e.g. unsupported link type, IP parse failure) are
// surfaced one packet at a time so the CLI can log-and-continue.
func (c *classicReader) Next() (*Frame, error) {
	for {
		hdr := make([]byte, 16)
		if _, err := io.ReadFull(c.r, hdr); err != nil {
			return nil, err
		}
		tsSec := c.bo.Uint32(hdr[0:4])
		tsFrac := c.bo.Uint32(hdr[4:8])
		caplen := c.bo.Uint32(hdr[8:12])
		origlen := c.bo.Uint32(hdr[12:16])
		if caplen > 0x10_000_000 {
			return nil, fmt.Errorf("classic pcap: implausible caplen %d", caplen)
		}
		pkt := make([]byte, caplen)
		if _, err := io.ReadFull(c.r, pkt); err != nil {
			return nil, fmt.Errorf("classic pcap: short packet body: %w", err)
		}
		ts := classicTimestamp(tsSec, tsFrac, c.nanos)
		frame, err := frameFromBytes(c.linkType, pkt, int(origlen), ts)
		if err == errSkip {
			continue
		}
		if err != nil {
			// Surface as a non-skip error so the CLI can log it. We
			// still continue on the NEXT iteration; the caller calls
			// Next() again.
			return nil, fmt.Errorf("packet @ %s: %v", ts.Format(time.RFC3339Nano), err)
		}
		return frame, nil
	}
}

func classicTimestamp(sec, frac uint32, nanos bool) time.Time {
	if nanos {
		return time.Unix(int64(sec), int64(frac)).UTC()
	}
	return time.Unix(int64(sec), int64(frac)*1000).UTC()
}
