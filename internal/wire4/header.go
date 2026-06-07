package wire4

import (
	"encoding/binary"
	"fmt"

	"github.com/ludomikula/dhcpdbg/internal/attrs"
	"github.com/ludomikula/dhcpdbg/internal/dict"
)

// header collects the BOOTP-header fields a packet draws from the pseudo-attrs
// (Opcode, Hardware-Type, ...) declared in dictionary.freeradius.internal.
type header struct {
	op         uint8
	htype      uint8
	hlen       uint8
	hops       uint8
	xid        uint32
	secs       uint16
	flags      uint16
	ciaddr     [4]byte
	yiaddr     [4]byte
	siaddr     [4]byte
	giaddr     [4]byte
	chaddr     [16]byte
	sname      [64]byte
	file       [128]byte
	packetType uint32 // Internal Packet-Type (273) — used to fill Message-Type.
}

func newHeader() *header { return &header{} }

func (h *header) absorb(p attrs.Pair) error {
	switch p.Attr.Code {
	case hdrOpcode:
		h.op = uint8(p.Value.Uint)
	case hdrHardwareType:
		h.htype = uint8(p.Value.Uint)
	case hdrHardwareAddressLen:
		h.hlen = uint8(p.Value.Uint)
	case hdrHopCount:
		h.hops = uint8(p.Value.Uint)
	case hdrTransactionID:
		h.xid = uint32(p.Value.Uint)
	case hdrNumberOfSeconds:
		h.secs = uint16(p.Value.Uint)
	case hdrFlags:
		h.flags = uint16(p.Value.Uint)
	case hdrClientIPAddress:
		copyIP(h.ciaddr[:], p.Value.IPv4)
	case hdrYourIPAddress:
		copyIP(h.yiaddr[:], p.Value.IPv4)
	case hdrServerIPAddress:
		copyIP(h.siaddr[:], p.Value.IPv4)
	case hdrGatewayIPAddress:
		copyIP(h.giaddr[:], p.Value.IPv4)
	case hdrClientHardwareAddr:
		if p.Value.Type == dict.TypeEther && len(p.Value.Bytes) == 6 {
			copy(h.chaddr[:], p.Value.Bytes)
			if h.hlen == 0 {
				h.hlen = 6
			}
		} else if len(p.Value.Bytes) > 0 {
			n := len(p.Value.Bytes)
			if n > 16 {
				n = 16
			}
			copy(h.chaddr[:n], p.Value.Bytes[:n])
			if h.hlen == 0 {
				h.hlen = uint8(n)
			}
		}
	case hdrServerHostName:
		copyStr(h.sname[:], p.Value.Str)
	case hdrBootFilename:
		copyStr(h.file[:], p.Value.Str)
	case hdrPacketType:
		h.packetType = uint32(p.Value.Uint)
	default:
		return fmt.Errorf("unknown internal attribute %d (%s)", p.Attr.Code, p.Attr.Name)
	}
	return nil
}

func (h *header) marshal(b []byte) []byte {
	hdrBuf := make([]byte, 236)
	hdrBuf[0] = h.op
	hdrBuf[1] = h.htype
	hdrBuf[2] = h.hlen
	hdrBuf[3] = h.hops
	binary.BigEndian.PutUint32(hdrBuf[4:8], h.xid)
	binary.BigEndian.PutUint16(hdrBuf[8:10], h.secs)
	binary.BigEndian.PutUint16(hdrBuf[10:12], h.flags)
	copy(hdrBuf[12:16], h.ciaddr[:])
	copy(hdrBuf[16:20], h.yiaddr[:])
	copy(hdrBuf[20:24], h.siaddr[:])
	copy(hdrBuf[24:28], h.giaddr[:])
	copy(hdrBuf[28:44], h.chaddr[:])
	copy(hdrBuf[44:108], h.sname[:])
	copy(hdrBuf[108:236], h.file[:])
	return append(b, hdrBuf...)
}

func copyIP(dst []byte, ip []byte) {
	if len(ip) == 4 {
		copy(dst, ip)
		return
	}
	if len(ip) == 16 {
		copy(dst, ip[12:])
		return
	}
}

func copyStr(dst []byte, s string) {
	n := len(s)
	if n > len(dst) {
		n = len(dst)
	}
	copy(dst, s[:n])
}
