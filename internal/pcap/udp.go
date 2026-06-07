package pcap

import (
	"encoding/binary"
	"fmt"
)

// stripUDP parses an 8-byte UDP header at the head of body, returning
// (srcPort, dstPort, payload). The Length field is honoured but capped
// at len(body) so truncated captures still surface the bytes we did
// receive. Checksum is NOT verified — DHCP checksums are often disabled
// at the source anyway, and a wrong checksum shouldn't stop the decoder.
func stripUDP(body []byte) (uint16, uint16, []byte, error) {
	if len(body) < 8 {
		return 0, 0, nil, fmt.Errorf("udp: short header (%d bytes)", len(body))
	}
	src := binary.BigEndian.Uint16(body[0:2])
	dst := binary.BigEndian.Uint16(body[2:4])
	length := int(binary.BigEndian.Uint16(body[4:6]))
	if length < 8 {
		return 0, 0, nil, fmt.Errorf("udp: bogus length %d", length)
	}
	payload := body[8:]
	if length-8 < len(payload) {
		payload = payload[:length-8]
	}
	return src, dst, payload, nil
}
