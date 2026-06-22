package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const (
	NbMagic       = uint32(0x4E425632) // "NBv2" LE
	NbVersion     = uint8(1)
	NbAddrIPv4    = uint8(0x04)
	NbAddrIPv6    = uint8(0x06)
	NbProtoTCP    = uint8(6)
	NbProtoUDP    = uint8(17)
	NbErrVersion  = uint8(0x01)
	NbErrToken    = uint8(0x02)
	NbProcNameMax = 64

	NbTcpHeaderBaseSize = 36
)

type NbTcpHeader struct {
	Magic       uint32
	Version     uint8
	AddrType    uint8
	Protocol    uint8
	ProcNameLen uint8
	DstPort     uint16
	SrcPort     uint16
	DstAddr     [16]byte
	Pid         uint32
	Token       uint32
	ProcName    string
}

// ParseTcpHeader reads a NetBridge TCP header from r.
// The header is variable-length: base 36 bytes + proc_name + padding.
func ParseTcpHeader(r io.Reader) (*NbTcpHeader, error) {
	base := make([]byte, NbTcpHeaderBaseSize)
	if _, err := io.ReadFull(r, base); err != nil {
		return nil, fmt.Errorf("read base header: %w", err)
	}

	h := &NbTcpHeader{}
	h.Magic = binary.LittleEndian.Uint32(base[0:4])
	h.Version = base[4]
	h.AddrType = base[5]
	h.Protocol = base[6]
	h.ProcNameLen = base[7]
	h.DstPort = binary.LittleEndian.Uint16(base[8:10])
	h.SrcPort = binary.LittleEndian.Uint16(base[10:12])
	copy(h.DstAddr[:], base[12:28])
	h.Pid = binary.LittleEndian.Uint32(base[28:32])
	h.Token = binary.LittleEndian.Uint32(base[32:36])

	if h.ProcNameLen > 0 {
		nameBuf := make([]byte, h.ProcNameLen)
		if _, err := io.ReadFull(r, nameBuf); err != nil {
			return nil, fmt.Errorf("read proc_name: %w", err)
		}
		h.ProcName = string(nameBuf)

		// Skip reserved padding to 4-byte boundary
		total := NbTcpHeaderBaseSize + int(h.ProcNameLen)
		pad := (4 - total%4) % 4
		if pad > 0 {
			io.ReadFull(r, make([]byte, pad))
		}
	}

	return h, nil
}

// DstHostPort returns the destination as "ip:port" string.
func (h *NbTcpHeader) DstHostPort() string {
	var ip net.IP
	if h.AddrType == NbAddrIPv4 {
		ip = net.IP(h.DstAddr[:4])
	} else {
		ip = net.IP(h.DstAddr[:])
	}
	return net.JoinHostPort(ip.String(), fmt.Sprintf("%d", h.DstPort))
}

// SendError sends an NbError packet to conn.
func SendError(conn io.Writer, code uint8) {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint32(b[0:4], NbMagic)
	b[4] = NbVersion
	b[5] = code
	conn.Write(b)
}
