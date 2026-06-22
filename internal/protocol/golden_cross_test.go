package protocol

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// TestGolden_C_Generated_TCP_Chrome reads the C-generated golden TCP header
// with "chrome.exe" and verifies Go parses it identically.
func TestGolden_C_Generated_TCP_Chrome(t *testing.T) {
	data := readGoldenFile(t, "golden_tcp_chrome.bin")

	hdr, err := ParseTcpHeader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("ParseTcpHeader: %v", err)
	}

	assert := func(field string, got, want interface{}) {
		t.Helper()
		if got != want {
			t.Errorf("%s: got %v, want %v", field, got, want)
		}
	}

	assert("Magic", hdr.Magic, uint32(0x4E425632))
	assert("Version", hdr.Version, uint8(1))
	assert("AddrType", hdr.AddrType, uint8(NbAddrIPv4))
	assert("Protocol", hdr.Protocol, uint8(NbProtoTCP))
	assert("ProcNameLen", hdr.ProcNameLen, uint8(10))
	assert("DstPort", hdr.DstPort, uint16(443))
	assert("SrcPort", hdr.SrcPort, uint16(54321))
	assert("Pid", hdr.Pid, uint32(0x1234))
	assert("Token", hdr.Token, uint32(0xDEADBEEF))
	assert("ProcName", hdr.ProcName, "chrome.exe")
	assert("DstHostPort", hdr.DstHostPort(), "1.1.1.1:443")
}

// TestGolden_C_Generated_TCP_NoName reads the C-generated golden TCP header
// without proc_name and verifies Go parses it.
func TestGolden_C_Generated_TCP_NoName(t *testing.T) {
	data := readGoldenFile(t, "golden_tcp_no_name.bin")

	hdr, err := ParseTcpHeader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("ParseTcpHeader: %v", err)
	}

	if hdr.ProcNameLen != 0 {
		t.Errorf("ProcNameLen = %d, want 0", hdr.ProcNameLen)
	}
	if hdr.ProcName != "" {
		t.Errorf("ProcName = %q, want empty", hdr.ProcName)
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
}

// TestGolden_C_Generated_TCP_IPv6 reads the C-generated golden TCP header
// with IPv6 destination and verifies Go parses it.
func TestGolden_C_Generated_TCP_IPv6(t *testing.T) {
	data := readGoldenFile(t, "golden_tcp_ipv6.bin")

	hdr, err := ParseTcpHeader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("ParseTcpHeader: %v", err)
	}

	if hdr.AddrType != NbAddrIPv6 {
		t.Errorf("AddrType = %d, want %d (IPv6)", hdr.AddrType, NbAddrIPv6)
	}
	if hdr.DstPort != 443 {
		t.Errorf("DstPort = %d, want 443", hdr.DstPort)
	}
	if hdr.SrcPort != 11111 {
		t.Errorf("SrcPort = %d, want 11111", hdr.SrcPort)
	}
	if hdr.Pid != 5555 {
		t.Errorf("Pid = %d, want 5555", hdr.Pid)
	}
	if hdr.Token != 0xCAFEBABE {
		t.Errorf("Token = 0x%08X, want 0xCAFEBABE", hdr.Token)
	}

	// Verify IPv6 address: 2001:db8::1
	expectedIPv6 := []byte{0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	for i, b := range hdr.DstAddr {
		if b != expectedIPv6[i] {
			t.Errorf("DstAddr[%d] = 0x%02X, want 0x%02X", i, b, expectedIPv6[i])
		}
	}

	if hdr.DstHostPort() != "[2001:db8::1]:443" {
		t.Errorf("DstHostPort = %q, want %q", hdr.DstHostPort(), "[2001:db8::1]:443")
	}
}

// TestGolden_C_Generated_UDP_Req reads the C-generated golden UDP request
// header + payload and verifies Go parses it.
func TestGolden_C_Generated_UDP_Req(t *testing.T) {
	data := readGoldenFile(t, "golden_udp_req.bin")

	hdr, payload, err := ParseUdpReqHeader(data)
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

// TestGolden_C_Generated_UDP_Resp reads the C-generated golden UDP response
// header and verifies Go's offset expectations match.
func TestGolden_C_Generated_UDP_Resp(t *testing.T) {
	data := readGoldenFile(t, "golden_udp_resp.bin")

	if len(data) != NbUdpRespHeaderSize {
		t.Fatalf("size = %d, want %d", len(data), NbUdpRespHeaderSize)
	}

	magic := binary.LittleEndian.Uint32(data[0:4])
	if magic != 0x4E425632 {
		t.Errorf("magic = 0x%08X", magic)
	}
	if data[5] != NbAddrIPv4 {
		t.Errorf("addr_type = %d", data[5])
	}
	srcPort := binary.LittleEndian.Uint16(data[8:10])
	if srcPort != 53 {
		t.Errorf("src_port = %d, want 53", srcPort)
	}
	// Verify src_addr at offset 12
	if data[12] != 0x08 || data[13] != 0x08 || data[14] != 0x08 || data[15] != 0x08 {
		t.Errorf("src_addr = %v, want [8,8,8,8,...]", data[12:16])
	}
	payloadLen := binary.LittleEndian.Uint16(data[28:30])
	if payloadLen != 16 {
		t.Errorf("payload_len = %d, want 16", payloadLen)
	}
}

// TestGolden_C_Generated_Error reads the C-generated golden error packet
// and verifies Go parses it.
func TestGolden_C_Generated_Error(t *testing.T) {
	data := readGoldenFile(t, "golden_error.bin")

	if len(data) != 8 {
		t.Fatalf("size = %d, want 8", len(data))
	}

	magic := binary.LittleEndian.Uint32(data[0:4])
	if magic != 0x4E425632 {
		t.Errorf("magic = 0x%08X", magic)
	}
	if data[4] != 1 {
		t.Errorf("version = %d, want 1", data[4])
	}
	if data[5] != NbErrToken {
		t.Errorf("error_code = %d, want %d (NB_ERR_TOKEN)", data[5], NbErrToken)
	}
}

// TestGolden_C_Generated_SizeVerification verifies all C-generated files
// have the expected sizes matching the protocol spec.
func TestGolden_C_Generated_SizeVerification(t *testing.T) {
	tests := []struct {
		file string
		want int
	}{
		{"golden_tcp_chrome.bin", 48},     // 36 base + 10 name + 2 pad
		{"golden_tcp_no_name.bin", 36},     // 36 base, already aligned
		{"golden_tcp_ipv6.bin", 36},        // 36 base, already aligned
		{"golden_udp_req.bin", 64},         // 56 header + 8 payload
		{"golden_udp_resp.bin", 32},        // 32 fixed
		{"golden_error.bin", 8},            // 8 fixed
	}

	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			path := filepath.Join("testdata", tt.file)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", tt.file, err)
			}
			if len(data) != tt.want {
				t.Errorf("%s: size = %d, want %d", tt.file, len(data), tt.want)
			}
		})
	}
}

func readGoldenFile(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join("testdata", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return data
}
