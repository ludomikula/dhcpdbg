package pcap

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// NewReader inspects the first 4 bytes of r to pick between the classic
// libpcap and the pcapng formats, then returns the matching Reader.
//
//	0xa1b2c3d4 / 0xd4c3b2a1   - classic libpcap (microsecond or nanosecond)
//	0x0a0d0d0a               - pcapng Section Header Block (block type)
//
// Anything else is rejected with a clear error. The 4 bytes consumed for
// the sniff are pushed back onto the reader so the concrete reader sees
// the full header.
func NewReader(r io.Reader) (Reader, error) {
	br := bufio.NewReader(r)
	magic, err := br.Peek(4)
	if err != nil {
		return nil, fmt.Errorf("pcap: read magic: %w", err)
	}
	be := binary.BigEndian.Uint32(magic)
	le := binary.LittleEndian.Uint32(magic)
	switch {
	case le == 0xa1b2c3d4, le == 0xd4c3b2a1, be == 0xa1b2c3d4, be == 0xd4c3b2a1,
		le == 0xa1b23c4d, be == 0xa1b23c4d: // 0xa1b23c4d = classic with nanosecond timestamps
		return newClassicReader(br)
	case le == 0x0a0d0d0a, be == 0x0a0d0d0a:
		return newPcapngReader(br)
	}
	return nil, fmt.Errorf("pcap: not a libpcap or pcapng file (magic %#08x)", be)
}

// errEOF unifies the io.EOF / io.ErrUnexpectedEOF surface for callers
// that want to stop iterating on EOF without distinguishing the two.
func isEOF(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}
