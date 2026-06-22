package protocol

import (
	"encoding/binary"
	"fmt"
	"net"
)

const (
	NbUdpReqHeaderSize  = 56
	NbUdpRespHeaderSize = 32
)

type NbUdpReqHeader struct {
	Magic       uint32
	Version     uint8
	AddrType    uint8
	Protocol    uint8
	Reserved    uint8
	DstPort     uint16
	SrcPort     uint16
	DstAddr     [16]byte
	SrcAddr     [16]byte
	Pid         uint32
	Token       uint32
	PayloadLen  uint16
	Reserved2   uint16
}

type NbUdpRespHeader struct {
	Magic       uint32
	Version     uint8
	AddrType    uint8
	Reserved    [2]byte
	SrcPort     uint16
	Reserved2   uint16
	SrcAddr     [16]byte
	PayloadLen  uint16
	Reserved3   uint16
}

// ParseUdpReqHeader parses a NetBridge UDP request header from data.
// Returns the header and payload slice (no copy).
func ParseUdpReqHeader(data []byte) (*NbUdpReqHeader, []byte, error) {
	if len(data) < NbUdpReqHeaderSize {
		return nil, nil, fmt.Errorf("packet too short: %d < %d", len(data), NbUdpReqHeaderSize)
	}

	h := &NbUdpReqHeader{}
	h.Magic = binary.LittleEndian.Uint32(data[0:4])
	h.Version = data[4]
	h.AddrType = data[5]
	h.Protocol = data[6]
	h.Reserved = data[7]
	h.DstPort = binary.LittleEndian.Uint16(data[8:10])
	h.SrcPort = binary.LittleEndian.Uint16(data[10:12])
	copy(h.DstAddr[:], data[12:28])
	copy(h.SrcAddr[:], data[28:44])
	h.Pid = binary.LittleEndian.Uint32(data[44:48])
	h.Token = binary.LittleEndian.Uint32(data[48:52])
	h.PayloadLen = binary.LittleEndian.Uint16(data[52:54])
	h.Reserved2 = binary.LittleEndian.Uint16(data[54:56])

	if int(h.PayloadLen) > len(data)-NbUdpReqHeaderSize {
		return nil, nil, fmt.Errorf("payload_len %d exceeds available data %d", h.PayloadLen, len(data)-NbUdpReqHeaderSize)
	}

	payload := data[NbUdpReqHeaderSize : NbUdpReqHeaderSize+int(h.PayloadLen)]
	return h, payload, nil
}

// BuildUdpRespHeader creates a NetBridge UDP response header.
func BuildUdpRespHeader(addrType uint8, srcIP net.IP, srcPort uint16, payloadLen uint16) []byte {
	b := make([]byte, NbUdpRespHeaderSize)
	binary.LittleEndian.PutUint32(b[0:4], NbMagic)
	b[4] = NbVersion
	b[5] = addrType
	binary.LittleEndian.PutUint16(b[8:10], srcPort)

	if ip4 := srcIP.To4(); ip4 != nil {
		copy(b[12:28], ip4)
	} else if ip16 := srcIP.To16(); ip16 != nil {
		copy(b[12:28], ip16)
	}

	binary.LittleEndian.PutUint16(b[28:30], payloadLen)
	return b
}
