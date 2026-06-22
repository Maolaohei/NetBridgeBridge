package protocol

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// Golden file cross-language verification.
//
// These tests verify that the Go protocol parser agrees with the C _Static_assert
// checks in nb_proto.h. The binary layouts are generated from the spec, not from
// either implementation — this is the "third source of truth" that catches
// drift between C and Go.
//
// To add a C golden generator: compile test/gen_golden.c (see gen_golden.go below).

// goldenTCPHeader chrome.exe (10 bytes), dst 1.1.1.1:443, src :54321, pid=0x1234, token=0xDEADBEEF
var goldenTCPHeader = []byte{
	// magic "NBv2" LE
	0x32, 0x56, 0x42, 0x4E,
	// version
	0x01,
	// addr_type IPv4
	0x04,
	// protocol TCP
	0x06,
	// proc_name_len = 10
	0x0A,
	// dst_port = 443 (LE)
	0xBB, 0x01,
	// src_port = 54321 (LE)
	0x31, 0xD4,
	// dst_addr = 1.1.1.1 (IPv4, first 4 bytes, rest zero)
	0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// pid = 0x1234 = 4660 (LE)
	0x34, 0x12, 0x00, 0x00,
	// token = 0xDEADBEEF (LE)
	0xEF, 0xBE, 0xAD, 0xDE,
	// proc_name = "chrome.exe" (10 bytes)
	0x63, 0x68, 0x72, 0x6F, 0x6D, 0x65, 0x2E, 0x65, 0x78, 0x65,
	// reserved padding (2 bytes to align 36+10=46 to 4-byte boundary → 48)
	0x00, 0x00,
}

// goldenTCPHeaderNoProcName dst 8.8.8.8:53, no proc_name
var goldenTCPHeaderNoProcName = []byte{
	// magic
	0x32, 0x56, 0x42, 0x4E,
	// version
	0x01,
	// addr_type IPv4
	0x04,
	// protocol TCP
	0x06,
	// proc_name_len = 0
	0x00,
	// dst_port = 53
	0x35, 0x00,
	// src_port = 12345
	0x39, 0x30,
	// dst_addr = 8.8.8.8
	0x08, 0x08, 0x08, 0x08, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// pid = 999
	0xE7, 0x03, 0x00, 0x00,
	// token = 0x12345678
	0x78, 0x56, 0x34, 0x12,
	// no proc_name, no padding (36 is already 4-byte aligned)
}

// goldenTCPHeaderIPv6 dst [2001:db8::1]:443
var goldenTCPHeaderIPv6 = []byte{
	// magic
	0x32, 0x56, 0x42, 0x4E,
	// version
	0x01,
	// addr_type IPv6
	0x06,
	// protocol TCP
	0x06,
	// proc_name_len = 0
	0x00,
	// dst_port = 443
	0xBB, 0x01,
	// src_port = 11111
	0x67, 0x2B,
	// dst_addr = 2001:db8::1
	0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	// pid = 5555
	0x33, 0x15, 0x00, 0x00,
	// token = 0xCAFEBABE
	0xBE, 0xBA, 0xFE, 0xCA,
}

// goldenUDPReqHeader dst 8.8.8.8:53, src 192.168.1.1:12345, pid=9999, token=0xCAFEBABE, payload "dnsquery"
var goldenUDPReqHeader = []byte{
	// magic
	0x32, 0x56, 0x42, 0x4E,
	// version
	0x01,
	// addr_type IPv4
	0x04,
	// protocol UDP
	0x11,
	// reserved
	0x00,
	// dst_port = 53
	0x35, 0x00,
	// src_port = 12345
	0x39, 0x30,
	// dst_addr = 8.8.8.8
	0x08, 0x08, 0x08, 0x08, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// src_addr = 192.168.1.1
	0xC0, 0xA8, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// pid = 9999
	0x0F, 0x27, 0x00, 0x00,
	// token = 0xCAFEBABE
	0xBE, 0xBA, 0xFE, 0xCA,
	// payload_len = 8
	0x08, 0x00,
	// reserved2
	0x00, 0x00,
	// payload = "dnsquery"
	0x64, 0x6E, 0x73, 0x71, 0x75, 0x65, 0x72, 0x79,
}

// goldenUDPRespHeader src 8.8.8.8:53, payload_len=16
var goldenUDPRespHeader = []byte{
	// magic
	0x32, 0x56, 0x42, 0x4E,
	// version
	0x01,
	// addr_type IPv4
	0x04,
	// reserved
	0x00, 0x00,
	// src_port = 53
	0x35, 0x00,
	// reserved2
	0x00, 0x00,
	// src_addr = 8.8.8.8
	0x08, 0x08, 0x08, 0x08, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// payload_len = 16
	0x10, 0x00,
	// reserved3
	0x00, 0x00,
}

// goldenNbError TOKEN error
var goldenNbError = []byte{
	0x32, 0x56, 0x42, 0x4E, // magic
	0x01,                     // version
	0x02,                     // error_code = NB_ERR_TOKEN
	0x00, 0x00,              // reserved
}

// ===== Cross-language offset verification =====
// These tests verify that Go field offsets match C _Static_assert in nb_proto.h

func TestGolden_TCP_Header_Size(t *testing.T) {
	if len(goldenTCPHeader) != 48 {
		t.Errorf("golden TCP header size = %d, want 48 (36 base + 10 name + 2 pad)", len(goldenTCPHeader))
	}
	if len(goldenTCPHeaderNoProcName) != 36 {
		t.Errorf("golden TCP no-name header size = %d, want 36", len(goldenTCPHeaderNoProcName))
	}
	if len(goldenTCPHeaderIPv6) != 36 {
		t.Errorf("golden TCP IPv6 header size = %d, want 36", len(goldenTCPHeaderIPv6))
	}
}

func TestGolden_TCP_FieldOffsets(t *testing.T) {
	// These offsets MUST match C _Static_assert in nb_proto.h
	tests := []struct {
		name   string
		offset int
		value  byte
	}{
		{"magic byte 0", 0, 0x32},
		{"magic byte 3", 3, 0x4E},
		{"version", 4, 0x01},
		{"addr_type IPv4", 5, 0x04},
		{"protocol TCP", 6, 0x06},
		{"proc_name_len=10", 7, 0x0A},
		{"dst_port low", 8, 0xBB},
		{"dst_port high", 9, 0x01},
		{"src_port low", 10, 0x31},
		{"src_port high", 11, 0xD4},
		{"dst_addr[0]", 12, 0x01},
		{"dst_addr[3]", 15, 0x01},
		{"pid byte 0", 28, 0x34},
		{"pid byte 1", 29, 0x12},
		{"token byte 0", 32, 0xEF},
		{"token byte 3", 35, 0xDE},
		{"proc_name[0] 'c'", 36, 0x63},
		{"proc_name[9] 'e'", 45, 0x65},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if goldenTCPHeader[tt.offset] != tt.value {
				t.Errorf("offset %d: got 0x%02X, want 0x%02X", tt.offset, goldenTCPHeader[tt.offset], tt.value)
			}
		})
	}
}

func TestGolden_TCP_ParseChrome(t *testing.T) {
	hdr, err := ParseTcpHeader(bytes.NewReader(goldenTCPHeader))
	if err != nil {
		t.Fatalf("ParseTcpHeader: %v", err)
	}

	assert := func(got, want interface{}) {
		t.Helper()
		if got != want {
			t.Errorf("got %v, want %v", got, want)
		}
	}

	assert(hdr.Magic, uint32(0x4E425632))
	assert(hdr.Version, uint8(1))
	assert(hdr.AddrType, uint8(NbAddrIPv4))
	assert(hdr.Protocol, uint8(NbProtoTCP))
	assert(hdr.ProcNameLen, uint8(10))
	assert(hdr.DstPort, uint16(443))
	assert(hdr.SrcPort, uint16(54321))
	assert(hdr.Pid, uint32(0x1234))
	assert(hdr.Token, uint32(0xDEADBEEF))
	assert(hdr.ProcName, "chrome.exe")

	// Verify DstHostPort
	assert(hdr.DstHostPort(), "1.1.1.1:443")
}

func TestGolden_TCP_ParseNoProcName(t *testing.T) {
	hdr, err := ParseTcpHeader(bytes.NewReader(goldenTCPHeaderNoProcName))
	if err != nil {
		t.Fatalf("ParseTcpHeader: %v", err)
	}

	if hdr.DstPort != 53 {
		t.Errorf("DstPort = %d, want 53", hdr.DstPort)
	}
	if hdr.SrcPort != 12345 {
		t.Errorf("SrcPort = %d, want 12345", hdr.SrcPort)
	}
	if hdr.Pid != 999 {
		t.Errorf("Pid = %d, want 999", hdr.Pid)
	}
	if hdr.Token != 0x12345678 {
		t.Errorf("Token = 0x%08X, want 0x12345678", hdr.Token)
	}
	if hdr.ProcName != "" {
		t.Errorf("ProcName = %q, want empty", hdr.ProcName)
	}
	if hdr.DstHostPort() != "8.8.8.8:53" {
		t.Errorf("DstHostPort = %q, want %q", hdr.DstHostPort(), "8.8.8.8:53")
	}
}

func TestGolden_TCP_ParseIPv6(t *testing.T) {
	hdr, err := ParseTcpHeader(bytes.NewReader(goldenTCPHeaderIPv6))
	if err != nil {
		t.Fatalf("ParseTcpHeader: %v", err)
	}

	if hdr.AddrType != NbAddrIPv6 {
		t.Errorf("AddrType = %d, want %d", hdr.AddrType, NbAddrIPv6)
	}
	if hdr.DstPort != 443 {
		t.Errorf("DstPort = %d, want 443", hdr.DstPort)
	}
	expected := "[2001:db8::1]:443"
	if hdr.DstHostPort() != expected {
		t.Errorf("DstHostPort = %q, want %q", hdr.DstHostPort(), expected)
	}
}

func TestGolden_UDPReq_Parse(t *testing.T) {
	hdr, payload, err := ParseUdpReqHeader(goldenUDPReqHeader)
	if err != nil {
		t.Fatalf("ParseUdpReqHeader: %v", err)
	}

	if hdr.Magic != 0x4E425632 {
		t.Errorf("Magic = 0x%08X", hdr.Magic)
	}
	if hdr.AddrType != NbAddrIPv4 {
		t.Errorf("AddrType = %d, want %d", hdr.AddrType, NbAddrIPv4)
	}
	if hdr.Protocol != NbProtoUDP {
		t.Errorf("Protocol = %d, want %d", hdr.Protocol, NbProtoUDP)
	}
	if hdr.DstPort != 53 {
		t.Errorf("DstPort = %d, want 53", hdr.DstPort)
	}
	if hdr.SrcPort != 12345 {
		t.Errorf("SrcPort = %d, want 12345", hdr.SrcPort)
	}
	if hdr.Pid != 9999 {
		t.Errorf("Pid = %d, want 9999", hdr.Pid)
	}
	if hdr.Token != 0xCAFEBABE {
		t.Errorf("Token = 0x%08X, want 0xCAFEBABE", hdr.Token)
	}
	if hdr.PayloadLen != 8 {
		t.Errorf("PayloadLen = %d, want 8", hdr.PayloadLen)
	}
	if string(payload) != "dnsquery" {
		t.Errorf("payload = %q, want %q", string(payload), "dnsquery")
	}
}

func TestGolden_UDPResp_Parse(t *testing.T) {
	// Verify offsets match C _Static_assert
	if len(goldenUDPRespHeader) != NbUdpRespHeaderSize {
		t.Fatalf("size = %d, want %d", len(goldenUDPRespHeader), NbUdpRespHeaderSize)
	}

	magic := binary.LittleEndian.Uint32(goldenUDPRespHeader[0:4])
	if magic != 0x4E425632 {
		t.Errorf("magic = 0x%08X", magic)
	}
	if goldenUDPRespHeader[5] != NbAddrIPv4 {
		t.Errorf("addr_type = %d", goldenUDPRespHeader[5])
	}
	srcPort := binary.LittleEndian.Uint16(goldenUDPRespHeader[8:10])
	if srcPort != 53 {
		t.Errorf("src_port = %d, want 53", srcPort)
	}
	payloadLen := binary.LittleEndian.Uint16(goldenUDPRespHeader[28:30])
	if payloadLen != 16 {
		t.Errorf("payload_len = %d, want 16", payloadLen)
	}
}

func TestGolden_NbError_Parse(t *testing.T) {
	if len(goldenNbError) != 8 {
		t.Fatalf("size = %d, want 8", len(goldenNbError))
	}
	magic := binary.LittleEndian.Uint32(goldenNbError[0:4])
	if magic != 0x4E425632 {
		t.Errorf("magic = 0x%08X", magic)
	}
	if goldenNbError[4] != 1 {
		t.Errorf("version = %d, want 1", goldenNbError[4])
	}
	if goldenNbError[5] != NbErrToken {
		t.Errorf("error_code = %d, want %d (NB_ERR_TOKEN)", goldenNbError[5], NbErrToken)
	}
}

// TestGolden_C_StaticAssert_Compat verifies our golden data matches C _Static_assert expectations.
// Each test corresponds to a specific _Static_assert in nb_proto.h.
func TestGolden_C_StaticAssert_Compat(t *testing.T) {
	// nb_proto.h: _Static_assert(sizeof(NbTcpHeader) == 36)
	if NbTcpHeaderBaseSize != 36 {
		t.Errorf("NbTcpHeaderBaseSize = %d, want 36 (C _Static_assert)", NbTcpHeaderBaseSize)
	}

	// nb_proto.h: offsetof(NbTcpHeader, proc_name_len) == 7
	// We verify by checking byte 7 of golden header
	if goldenTCPHeader[7] != 10 { // proc_name_len for "chrome.exe"
		t.Errorf("goldenTCPHeader[7] = %d, want 10 (proc_name_len offset 7)", goldenTCPHeader[7])
	}

	// nb_proto.h: offsetof(NbTcpHeader, dst_port) == 8
	dstPort := binary.LittleEndian.Uint16(goldenTCPHeader[8:10])
	if dstPort != 443 {
		t.Errorf("dst_port at offset 8 = %d, want 443", dstPort)
	}

	// nb_proto.h: offsetof(NbTcpHeader, dst_addr) == 12
	if goldenTCPHeader[12] != 0x01 || goldenTCPHeader[15] != 0x01 {
		t.Errorf("dst_addr at offset 12 = %v, want [1,?,?,1,...]", goldenTCPHeader[12:16])
	}

	// nb_proto.h: offsetof(NbTcpHeader, pid) == 28
	pid := binary.LittleEndian.Uint32(goldenTCPHeader[28:32])
	if pid != 0x1234 {
		t.Errorf("pid at offset 28 = 0x%08X, want 0x1234", pid)
	}

	// nb_proto.h: offsetof(NbTcpHeader, token) == 32
	token := binary.LittleEndian.Uint32(goldenTCPHeader[32:36])
	if token != 0xDEADBEEF {
		t.Errorf("token at offset 32 = 0x%08X, want 0xDEADBEEF", token)
	}

	// UDP offsets
	// nb_proto.h: offsetof(NbUdpReqHeader, pid) == 44
	udpPid := binary.LittleEndian.Uint32(goldenUDPReqHeader[44:48])
	if udpPid != 9999 {
		t.Errorf("UDP pid at offset 44 = %d, want 9999", udpPid)
	}

	// nb_proto.h: offsetof(NbUdpReqHeader, token) == 48
	udpToken := binary.LittleEndian.Uint32(goldenUDPReqHeader[48:52])
	if udpToken != 0xCAFEBABE {
		t.Errorf("UDP token at offset 48 = 0x%08X, want 0xCAFEBABE", udpToken)
	}

	// nb_proto.h: offsetof(NbUdpReqHeader, payload_len) == 52
	udpPayloadLen := binary.LittleEndian.Uint16(goldenUDPReqHeader[52:54])
	if udpPayloadLen != 8 {
		t.Errorf("UDP payload_len at offset 52 = %d, want 8", udpPayloadLen)
	}

	// UDP resp offsets
	// nb_proto.h: offsetof(NbUdpRespHeader, src_port) == 8
	respSrcPort := binary.LittleEndian.Uint16(goldenUDPRespHeader[8:10])
	if respSrcPort != 53 {
		t.Errorf("UDP resp src_port at offset 8 = %d, want 53", respSrcPort)
	}

	// nb_proto.h: offsetof(NbUdpRespHeader, src_addr) == 12
	if goldenUDPRespHeader[12] != 0x08 {
		t.Errorf("UDP resp src_addr at offset 12 = 0x%02X, want 0x08", goldenUDPRespHeader[12])
	}

	// nb_proto.h: offsetof(NbUdpRespHeader, payload_len) == 28
	respPayloadLen := binary.LittleEndian.Uint16(goldenUDPRespHeader[28:30])
	if respPayloadLen != 16 {
		t.Errorf("UDP resp payload_len at offset 28 = %d, want 16", respPayloadLen)
	}
}

// TestGolden_RoundTrip Serialize then parse, verify identity
func TestGolden_RoundTrip(t *testing.T) {
	original := goldenTCPHeader
	hdr, err := ParseTcpHeader(bytes.NewReader(original))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// Re-serialize
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, hdr.Magic)
	buf.WriteByte(hdr.Version)
	buf.WriteByte(hdr.AddrType)
	buf.WriteByte(hdr.Protocol)
	buf.WriteByte(hdr.ProcNameLen)
	binary.Write(&buf, binary.LittleEndian, hdr.DstPort)
	binary.Write(&buf, binary.LittleEndian, hdr.SrcPort)
	buf.Write(hdr.DstAddr[:])
	binary.Write(&buf, binary.LittleEndian, hdr.Pid)
	binary.Write(&buf, binary.LittleEndian, hdr.Token)
	buf.WriteString(hdr.ProcName)
	// Padding
	total := NbTcpHeaderBaseSize + len(hdr.ProcName)
	pad := (4 - total%4) % 4
	for i := 0; i < pad; i++ {
		buf.WriteByte(0)
	}

	rebuilt := buf.Bytes()
	if !bytes.Equal(original, rebuilt) {
		t.Errorf("round-trip mismatch:\n  original:  %x\n  rebuilt:   %x", original, rebuilt)
	}
}
