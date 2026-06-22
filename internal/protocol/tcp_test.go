package protocol

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestParseTcpHeader_IPv4(t *testing.T) {
	// Build a valid NbTcpHeader: magic, version, addr_type, protocol, proc_name_len, dst_port, src_port, dst_addr[16], pid, token
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint32(0x4E425632)) // magic
	buf.WriteByte(1)                                             // version
	buf.WriteByte(NbAddrIPv4)                                    // addr_type
	buf.WriteByte(NbProtoTCP)                                    // protocol
	buf.WriteByte(10)                                            // proc_name_len
	binary.Write(buf, binary.LittleEndian, uint16(443))         // dst_port
	binary.Write(buf, binary.LittleEndian, uint16(54321))       // src_port
	buf.Write([]byte{1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) // dst_addr 1.1.1.1
	binary.Write(buf, binary.LittleEndian, uint32(1234))        // pid
	binary.Write(buf, binary.LittleEndian, uint32(0xDEADBEEF))  // token
	buf.WriteString("chrome.exe")                                // proc_name (10 bytes)
	buf.WriteByte(0)                                             // padding (1 byte to align to 4)

	hdr, err := ParseTcpHeader(buf)
	if err != nil {
		t.Fatalf("ParseTcpHeader: %v", err)
	}

	if hdr.Magic != 0x4E425632 {
		t.Errorf("Magic = 0x%08X, want 0x4E425632", hdr.Magic)
	}
	if hdr.Version != 1 {
		t.Errorf("Version = %d, want 1", hdr.Version)
	}
	if hdr.AddrType != NbAddrIPv4 {
		t.Errorf("AddrType = %d, want %d", hdr.AddrType, NbAddrIPv4)
	}
	if hdr.Protocol != NbProtoTCP {
		t.Errorf("Protocol = %d, want %d", hdr.Protocol, NbProtoTCP)
	}
	if hdr.ProcNameLen != 10 {
		t.Errorf("ProcNameLen = %d, want 10", hdr.ProcNameLen)
	}
	if hdr.DstPort != 443 {
		t.Errorf("DstPort = %d, want 443", hdr.DstPort)
	}
	if hdr.SrcPort != 54321 {
		t.Errorf("SrcPort = %d, want 54321", hdr.SrcPort)
	}
	if hdr.Pid != 1234 {
		t.Errorf("Pid = %d, want 1234", hdr.Pid)
	}
	if hdr.Token != 0xDEADBEEF {
		t.Errorf("Token = 0x%08X, want 0xDEADBEEF", hdr.Token)
	}
	if hdr.ProcName != "chrome.exe" {
		t.Errorf("ProcName = %q, want %q", hdr.ProcName, "chrome.exe")
	}
}

func TestParseTcpHeader_NoProcName(t *testing.T) {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint32(0x4E425632))
	buf.WriteByte(1)
	buf.WriteByte(NbAddrIPv4)
	buf.WriteByte(NbProtoTCP)
	buf.WriteByte(0) // proc_name_len = 0
	binary.Write(buf, binary.LittleEndian, uint16(80))
	binary.Write(buf, binary.LittleEndian, uint16(12345))
	buf.Write(make([]byte, 16)) // dst_addr
	binary.Write(buf, binary.LittleEndian, uint32(999))
	binary.Write(buf, binary.LittleEndian, uint32(0x12345678))

	hdr, err := ParseTcpHeader(buf)
	if err != nil {
		t.Fatalf("ParseTcpHeader: %v", err)
	}
	if hdr.ProcNameLen != 0 {
		t.Errorf("ProcNameLen = %d, want 0", hdr.ProcNameLen)
	}
	if hdr.ProcName != "" {
		t.Errorf("ProcName = %q, want empty", hdr.ProcName)
	}
	if hdr.DstPort != 80 {
		t.Errorf("DstPort = %d, want 80", hdr.DstPort)
	}
}

func TestParseTcpHeader_IPv6(t *testing.T) {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint32(0x4E425632))
	buf.WriteByte(1)
	buf.WriteByte(NbAddrIPv6) // IPv6
	buf.WriteByte(NbProtoTCP)
	buf.WriteByte(0)
	binary.Write(buf, binary.LittleEndian, uint16(443))
	binary.Write(buf, binary.LittleEndian, uint16(11111))
	// IPv6 address: 2001:db8::1
	buf.Write([]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	binary.Write(buf, binary.LittleEndian, uint32(5555))
	binary.Write(buf, binary.LittleEndian, uint32(0xABCDEF01))

	hdr, err := ParseTcpHeader(buf)
	if err != nil {
		t.Fatalf("ParseTcpHeader: %v", err)
	}
	if hdr.AddrType != NbAddrIPv6 {
		t.Errorf("AddrType = %d, want %d", hdr.AddrType, NbAddrIPv6)
	}
	// Verify IPv6 address
	expectedIPv6 := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	for i, b := range hdr.DstAddr {
		if b != expectedIPv6[i] {
			t.Errorf("DstAddr[%d] = 0x%02X, want 0x%02X", i, b, expectedIPv6[i])
		}
	}
}

func TestParseTcpHeader_TooShort(t *testing.T) {
	buf := bytes.NewReader([]byte{0x01, 0x02, 0x03}) // only 3 bytes
	_, err := ParseTcpHeader(buf)
	if err == nil {
		t.Error("expected error for short buffer, got nil")
	}
}

func TestDstHostPort_IPv4(t *testing.T) {
	hdr := &NbTcpHeader{
		AddrType: NbAddrIPv4,
		DstPort:  443,
		DstAddr:  [16]byte{1, 1, 1, 1},
	}
	got := hdr.DstHostPort()
	want := "1.1.1.1:443"
	if got != want {
		t.Errorf("DstHostPort() = %q, want %q", got, want)
	}
}

func TestDstHostPort_IPv6(t *testing.T) {
	hdr := &NbTcpHeader{
		AddrType: NbAddrIPv6,
		DstPort:  8080,
		DstAddr:  [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
	}
	got := hdr.DstHostPort()
	want := "[2001:db8::1]:8080"
	if got != want {
		t.Errorf("DstHostPort() = %q, want %q", got, want)
	}
}

func TestSendError(t *testing.T) {
	var buf bytes.Buffer
	SendError(&buf, NbErrToken)
	data := buf.Bytes()
	if len(data) != 8 {
		t.Fatalf("SendError wrote %d bytes, want 8", len(data))
	}
	magic := binary.LittleEndian.Uint32(data[0:4])
	if magic != 0x4E425632 {
		t.Errorf("magic = 0x%08X, want 0x4E425632", magic)
	}
	if data[4] != NbVersion {
		t.Errorf("version = %d, want %d", data[4], NbVersion)
	}
	if data[5] != NbErrToken {
		t.Errorf("error_code = %d, want %d", data[5], NbErrToken)
	}
}

func TestConstants(t *testing.T) {
	if NbMagic != 0x4E425632 {
		t.Errorf("NbMagic = 0x%08X, want 0x4E425632", NbMagic)
	}
	if NbVersion != 1 {
		t.Errorf("NbVersion = %d, want 1", NbVersion)
	}
	if NbTcpHeaderBaseSize != 36 {
		t.Errorf("NbTcpHeaderBaseSize = %d, want 36", NbTcpHeaderBaseSize)
	}
}
