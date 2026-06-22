package protocol

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestParseUdpReqHeader(t *testing.T) {
	// Build a valid 56-byte NbUdpReqHeader + 10-byte payload
	data := make([]byte, NbUdpReqHeaderSize+10)

	// Fill header fields
	binary.LittleEndian.PutUint32(data[0:4], 0x4E425632) // magic
	data[4] = 1                                            // version
	data[5] = NbAddrIPv4                                   // addr_type
	data[6] = NbProtoUDP                                   // protocol
	data[7] = 0                                            // reserved
	binary.LittleEndian.PutUint16(data[8:10], 53)          // dst_port
	binary.LittleEndian.PutUint16(data[10:12], 12345)      // src_port
	copy(data[12:28], []byte{8, 8, 8, 8})                  // dst_addr 8.8.8.8
	copy(data[28:44], []byte{192, 168, 1, 1})              // src_addr
	binary.LittleEndian.PutUint32(data[44:48], 9999)       // pid
	binary.LittleEndian.PutUint32(data[48:52], 0xCAFEBABE) // token
	binary.LittleEndian.PutUint16(data[52:54], 9)          // payload_len
	// Fill payload
	copy(data[56:65], []byte("hello dns"))

	hdr, payload, err := ParseUdpReqHeader(data)
	if err != nil {
		t.Fatalf("ParseUdpReqHeader: %v", err)
	}

	if hdr.Magic != 0x4E425632 {
		t.Errorf("Magic = 0x%08X, want 0x4E425632", hdr.Magic)
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
	if hdr.PayloadLen != 9 {
		t.Errorf("PayloadLen = %d, want 9", hdr.PayloadLen)
	}
	if string(payload) != "hello dns" {
		t.Errorf("payload = %q, want %q", string(payload), "hello dns")
	}
}

func TestParseUdpReqHeader_TooShort(t *testing.T) {
	data := make([]byte, 10) // too short
	_, _, err := ParseUdpReqHeader(data)
	if err == nil {
		t.Error("expected error for short data, got nil")
	}
}

func TestParseUdpReqHeader_PayloadLenExceedsData(t *testing.T) {
	data := make([]byte, NbUdpReqHeaderSize+5)
	binary.LittleEndian.PutUint16(data[52:54], 100) // payload_len = 100, but only 5 bytes available
	_, _, err := ParseUdpReqHeader(data)
	if err == nil {
		t.Error("expected error for payload_len > available data, got nil")
	}
}

func TestBuildUdpRespHeader_IPv4(t *testing.T) {
	srcIP := net.IPv4(8, 8, 8, 8)
	hdr := BuildUdpRespHeader(NbAddrIPv4, srcIP, 53, 42)

	if len(hdr) != NbUdpRespHeaderSize {
		t.Fatalf("len(hdr) = %d, want %d", len(hdr), NbUdpRespHeaderSize)
	}

	magic := binary.LittleEndian.Uint32(hdr[0:4])
	if magic != 0x4E425632 {
		t.Errorf("magic = 0x%08X, want 0x4E425632", magic)
	}
	if hdr[5] != NbAddrIPv4 {
		t.Errorf("addr_type = %d, want %d", hdr[5], NbAddrIPv4)
	}
	srcPort := binary.LittleEndian.Uint16(hdr[8:10])
	if srcPort != 53 {
		t.Errorf("src_port = %d, want 53", srcPort)
	}
	// Check src_addr (bytes 12-28)
	if hdr[12] != 8 || hdr[13] != 8 || hdr[14] != 8 || hdr[15] != 8 {
		t.Errorf("src_addr = %v, want [8 8 8 8 ...]", hdr[12:16])
	}
	payloadLen := binary.LittleEndian.Uint16(hdr[28:30])
	if payloadLen != 42 {
		t.Errorf("payload_len = %d, want 42", payloadLen)
	}
}

func TestBuildUdpRespHeader_IPv6(t *testing.T) {
	srcIP := net.ParseIP("2001:db8::1")
	hdr := BuildUdpRespHeader(NbAddrIPv6, srcIP, 443, 100)

	if hdr[5] != NbAddrIPv6 {
		t.Errorf("addr_type = %d, want %d", hdr[5], NbAddrIPv6)
	}
	// Verify IPv6 address in header
	expected := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	for i, b := range hdr[12:28] {
		if b != expected[i] {
			t.Errorf("src_addr[%d] = 0x%02X, want 0x%02X", i, b, expected[i])
		}
	}
}

func TestParseUdpReqHeader_OffsetChecks(t *testing.T) {
	// Verify that field offsets match the C side nb_proto.h
	data := make([]byte, NbUdpReqHeaderSize)
	binary.LittleEndian.PutUint32(data[0:4], 0x4E425632)
	binary.LittleEndian.PutUint16(data[8:10], 111)    // dst_port at offset 8
	binary.LittleEndian.PutUint16(data[10:12], 222)   // src_port at offset 10
	binary.LittleEndian.PutUint32(data[44:48], 333)   // pid at offset 44
	binary.LittleEndian.PutUint32(data[48:52], 444)   // token at offset 48
	binary.LittleEndian.PutUint16(data[52:54], 0)     // payload_len at offset 52 (no payload)

	hdr, _, err := ParseUdpReqHeader(data)
	if err != nil {
		t.Fatalf("ParseUdpReqHeader: %v", err)
	}
	if hdr.DstPort != 111 {
		t.Errorf("DstPort = %d, want 111 (offset 8)", hdr.DstPort)
	}
	if hdr.SrcPort != 222 {
		t.Errorf("SrcPort = %d, want 222 (offset 10)", hdr.SrcPort)
	}
	if hdr.Pid != 333 {
		t.Errorf("Pid = %d, want 333 (offset 44)", hdr.Pid)
	}
	if hdr.Token != 444 {
		t.Errorf("Token = %d, want 444 (offset 48)", hdr.Token)
	}
	if hdr.PayloadLen != 0 {
		t.Errorf("PayloadLen = %d, want 0 (offset 52)", hdr.PayloadLen)
	}
}
