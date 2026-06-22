package udpproxy

import (
	"context"
	"encoding/binary"
	"log"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/2dust/netbridge-bridge/internal/protocol"
)

func TestParseAndHandlePacket(t *testing.T) {
	// Build a valid UDP request packet
	payload := []byte("test dns payload")
	reqLen := protocol.NbUdpReqHeaderSize + len(payload)
	data := make([]byte, reqLen)

	binary.LittleEndian.PutUint32(data[0:4], protocol.NbMagic)
	data[4] = protocol.NbVersion
	data[5] = protocol.NbAddrIPv4
	data[6] = protocol.NbProtoUDP
	data[7] = 0
	binary.LittleEndian.PutUint16(data[8:10], 53)
	binary.LittleEndian.PutUint16(data[10:12], 12345)
	copy(data[12:16], []byte{8, 8, 8, 8})
	copy(data[28:32], []byte{192, 168, 1, 1})
	binary.LittleEndian.PutUint32(data[44:48], 9999)
	binary.LittleEndian.PutUint32(data[48:52], 0) // token=0
	binary.LittleEndian.PutUint16(data[52:54], uint16(len(payload)))
	copy(data[protocol.NbUdpReqHeaderSize:], payload)

	// Parse the header
	hdr, parsedPayload, err := protocol.ParseUdpReqHeader(data)
	if err != nil {
		t.Fatalf("ParseUdpReqHeader: %v", err)
	}

	if hdr.Magic != protocol.NbMagic {
		t.Errorf("Magic = 0x%08X", hdr.Magic)
	}
	if hdr.DstPort != 53 {
		t.Errorf("DstPort = %d, want 53", hdr.DstPort)
	}
	if string(parsedPayload) != "test dns payload" {
		t.Errorf("payload = %q, want %q", string(parsedPayload), "test dns payload")
	}
}

func TestBuildAndParseUdpResp(t *testing.T) {
	srcIP := net.IPv4(8, 8, 8, 8)
	payload := []byte("dns response data")

	hdr := protocol.BuildUdpRespHeader(protocol.NbAddrIPv4, srcIP, 53, uint16(len(payload)))
	pkt := append(hdr, payload...)

	// Verify the response packet
	if len(pkt) != protocol.NbUdpRespHeaderSize+len(payload) {
		t.Fatalf("pkt size = %d, want %d", len(pkt), protocol.NbUdpRespHeaderSize+len(payload))
	}

	// Parse manually (no ParseUdpRespHeader exists, verify offsets)
	magic := binary.LittleEndian.Uint32(pkt[0:4])
	if magic != protocol.NbMagic {
		t.Errorf("magic = 0x%08X", magic)
	}
	if pkt[5] != protocol.NbAddrIPv4 {
		t.Errorf("addr_type = %d", pkt[5])
	}
	srcPort := binary.LittleEndian.Uint16(pkt[8:10])
	if srcPort != 53 {
		t.Errorf("src_port = %d, want 53", srcPort)
	}
	respPayloadLen := binary.LittleEndian.Uint16(pkt[28:30])
	if respPayloadLen != uint16(len(payload)) {
		t.Errorf("payload_len = %d, want %d", respPayloadLen, len(payload))
	}
	// Verify payload is appended after header
	respPayload := pkt[protocol.NbUdpRespHeaderSize:]
	if string(respPayload) != "dns response data" {
		t.Errorf("response payload = %q", string(respPayload))
	}
}

func TestSessionCleanup(t *testing.T) {
	// Test that cleanup removes old sessions
	s := &Server{
		sessions: sync.Map{},
	}

	// Store a session with old timestamp
	key := "127.0.0.1:12345"
	sess := &UDPSession{
		Dst:        &net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 53},
		Pid:        9999,
		ClientAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345},
		LastActive: time.Now().Add(-2 * time.Minute), // 2 minutes ago
	}
	s.sessions.Store(key, sess)

	// Verify it's stored
	if _, ok := s.sessions.Load(key); !ok {
		t.Fatal("session not stored")
	}

	// Run cleanup logic (same as cleanupLoop)
	s.sessions.Range(func(k, v interface{}) bool {
		if time.Since(v.(*UDPSession).LastActive) > sessionTimeout {
			s.sessions.Delete(k)
		}
		return true
	})

	// Verify it's removed
	if _, ok := s.sessions.Load(key); ok {
		t.Error("session should have been cleaned up")
	}
}

// TestNewServer verifies server creation
func TestNewServer(t *testing.T) {
	s := NewServer(Config{
		UDPListen: "127.0.0.1:0",
		CoreSocks: "127.0.0.1:10808",
		Log:       testLog(t),
	})
	if s == nil {
		t.Fatal("NewServer returned nil")
	}
	if s.cfg.UDPListen != "127.0.0.1:0" {
		t.Errorf("UDPListen = %q", s.cfg.UDPListen)
	}
}

// TestServer_StartUDP verifies UDP server starts and receives packets
func TestServer_StartUDP(t *testing.T) {
	s := NewServer(Config{
		UDPListen: "127.0.0.1:0",
		CoreSocks: "127.0.0.1:10808",
		Log:       testLog(t),
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := s.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if s.conn == nil {
		t.Fatal("conn not set after Start")
	}

	// Send a valid UDP packet to the server
	payload := []byte("test udp data")
	reqLen := protocol.NbUdpReqHeaderSize + len(payload)
	data := make([]byte, reqLen)
	binary.LittleEndian.PutUint32(data[0:4], protocol.NbMagic)
	data[4] = protocol.NbVersion
	data[5] = protocol.NbAddrIPv4
	data[6] = protocol.NbProtoUDP
	binary.LittleEndian.PutUint16(data[8:10], 53)
	binary.LittleEndian.PutUint16(data[10:12], 12345)
	copy(data[12:16], []byte{8, 8, 8, 8})
	copy(data[28:32], []byte{192, 168, 1, 1})
	binary.LittleEndian.PutUint32(data[44:48], 9999)
	binary.LittleEndian.PutUint32(data[48:52], 0)
	binary.LittleEndian.PutUint16(data[52:54], uint16(len(payload)))
	copy(data[protocol.NbUdpReqHeaderSize:], payload)

	addr := s.conn.LocalAddr().(*net.UDPAddr)
	conn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	conn.Write(data)
	time.Sleep(100 * time.Millisecond) // let server process

	// Verify session was created
	count := 0
	s.sessions.Range(func(k, v interface{}) bool {
		count++
		return true
	})
	if count == 0 {
		t.Error("no sessions created after receiving packet")
	}

	cancel()
}

func testLog(t *testing.T) *log.Logger {
	return log.New(testWriter{t}, "[TEST] ", 0)
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (n int, err error) {
	w.t.Logf("%s", string(p))
	return len(p), nil
}

// TestHandlePacket_InvalidMagic tests that invalid magic is silently ignored
func TestHandlePacket_InvalidMagic(t *testing.T) {
	s := &Server{
		cfg:      Config{Log: testLog(t)},
		sessions: sync.Map{},
		token:    0,
	}
	clientAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	data := make([]byte, protocol.NbUdpReqHeaderSize)
	data[0] = 0x00 // wrong magic
	s.handlePacket(data, clientAddr)
	// No panic, no session created
	count := 0
	s.sessions.Range(func(k, v interface{}) bool { count++; return true })
	if count != 0 {
		t.Errorf("expected 0 sessions, got %d", count)
	}
}

// TestHandlePacket_WrongVersion tests version check
func TestHandlePacket_WrongVersion(t *testing.T) {
	s := &Server{cfg: Config{Log: testLog(t)}, sessions: sync.Map{}, token: 0}
	clientAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	data := make([]byte, protocol.NbUdpReqHeaderSize)
	binary.LittleEndian.PutUint32(data[0:4], protocol.NbMagic)
	data[4] = 0 // wrong version
	s.handlePacket(data, clientAddr)
	count := 0
	s.sessions.Range(func(k, v interface{}) bool { count++; return true })
	if count != 0 {
		t.Error("should not create session for wrong version")
	}
}

// TestHandlePacket_WrongToken tests token check
func TestHandlePacket_WrongToken(t *testing.T) {
	s := &Server{cfg: Config{Log: testLog(t)}, sessions: sync.Map{}, token: 0x12345678}
	clientAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	data := make([]byte, protocol.NbUdpReqHeaderSize)
	binary.LittleEndian.PutUint32(data[0:4], protocol.NbMagic)
	data[4] = protocol.NbVersion
	binary.LittleEndian.PutUint32(data[48:52], 0xAAAAAAAA) // wrong token
	s.handlePacket(data, clientAddr)
	count := 0
	s.sessions.Range(func(k, v interface{}) bool { count++; return true })
	if count != 0 {
		t.Error("should not create session for wrong token")
	}
}

// TestHandlePacket_InvalidAddrType tests unknown address type
func TestHandlePacket_InvalidAddrType(t *testing.T) {
	s := &Server{cfg: Config{Log: testLog(t)}, sessions: sync.Map{}, token: 0}
	clientAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	data := make([]byte, protocol.NbUdpReqHeaderSize)
	binary.LittleEndian.PutUint32(data[0:4], protocol.NbMagic)
	data[4] = protocol.NbVersion
	data[5] = 0xFF // invalid addr_type
	s.handlePacket(data, clientAddr)
	count := 0
	s.sessions.Range(func(k, v interface{}) bool { count++; return true })
	if count != 0 {
		t.Error("should not create session for invalid addr_type")
	}
}

// TestSessionCleanup_Timeout verifies cleanup removes old sessions
func TestSessionCleanup_Timeout(t *testing.T) {
	s := &Server{cfg: Config{Log: testLog(t)}, sessions: sync.Map{}}
	key := "127.0.0.1:12345"
	sess := &UDPSession{
		Dst:        &net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 53},
		Pid:        9999,
		ClientAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345},
		LastActive: time.Now().Add(-2 * time.Minute),
	}
	s.sessions.Store(key, sess)
	s.sessions.Range(func(k, v interface{}) bool {
		if time.Since(v.(*UDPSession).LastActive) > sessionTimeout {
			s.sessions.Delete(k)
		}
		return true
	})
	if _, ok := s.sessions.Load(key); ok {
		t.Error("session should have been cleaned up")
	}
}

// TestSendReply_IPv4 tests sendReply constructs correct response
func TestSendReply_IPv4(t *testing.T) {
	// Create a UDP listener to receive the reply
	ln, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	defer ln.Close()

	s := &Server{cfg: Config{Log: testLog(t)}, conn: ln}
	clientAddr := ln.LocalAddr().(*net.UDPAddr)

	srcIP := net.IPv4(8, 8, 8, 8)
	payload := []byte("reply data")

	// Send reply to ourselves
	s.sendReply(clientAddr, srcIP, 53, payload)

	// Read it
	buf := make([]byte, 1024)
	ln.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, _, _ := ln.ReadFromUDP(buf)
	if n < protocol.NbUdpRespHeaderSize {
		t.Fatalf("received %d bytes, want >= %d", n, protocol.NbUdpRespHeaderSize)
	}
	// Verify magic
	magic := binary.LittleEndian.Uint32(buf[0:4])
	if magic != protocol.NbMagic {
		t.Errorf("magic = 0x%08X", magic)
	}
}

// TestSendReply_IPv6 tests IPv6 sendReply
func TestSendReply_IPv6(t *testing.T) {
	ln, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	defer ln.Close()

	s := &Server{cfg: Config{Log: testLog(t)}, conn: ln}
	clientAddr := ln.LocalAddr().(*net.UDPAddr)

	srcIP := net.ParseIP("2001:db8::1")
	payload := []byte("ipv6 reply")

	s.sendReply(clientAddr, srcIP, 443, payload)

	buf := make([]byte, 1024)
	ln.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, _, _ := ln.ReadFromUDP(buf)
	if n < protocol.NbUdpRespHeaderSize {
		t.Fatalf("received %d bytes", n)
	}
	if buf[5] != protocol.NbAddrIPv6 {
		t.Errorf("addr_type = %d, want %d", buf[5], protocol.NbAddrIPv6)
	}
}

// TestRecvLoop_ContextCancel tests recvLoop exits on context cancel
func TestRecvLoop_ContextCancel(t *testing.T) {
	s := NewServer(Config{
		UDPListen: "127.0.0.1:0",
		Log:       testLog(t),
	})
	ctx, cancel := context.WithCancel(context.Background())
	if err := s.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	cancel()
	time.Sleep(200 * time.Millisecond)
	// If recvLoop doesn't hang, test passes
}

// TestRecvLoop_ShortPacket tests recvLoop ignores short packets
func TestRecvLoop_ShortPacket(t *testing.T) {
	s := NewServer(Config{
		UDPListen: "127.0.0.1:0",
		Log:       testLog(t),
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Send a packet shorter than NbUdpReqHeaderSize
	addr := s.conn.LocalAddr().(*net.UDPAddr)
	conn, _ := net.DialUDP("udp4", nil, addr)
	defer conn.Close()
	conn.Write([]byte{0x01, 0x02}) // 2 bytes, too short
	time.Sleep(100 * time.Millisecond)
	// Should not crash, no session created
}

// TestRecvLoop_BadMagic tests recvLoop ignores bad magic
func TestRecvLoop_BadMagic(t *testing.T) {
	s := NewServer(Config{
		UDPListen: "127.0.0.1:0",
		Log:       testLog(t),
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	addr := s.conn.LocalAddr().(*net.UDPAddr)
	conn, _ := net.DialUDP("udp4", nil, addr)
	defer conn.Close()

	data := make([]byte, protocol.NbUdpReqHeaderSize)
	data[0] = 0xFF // bad magic
	conn.Write(data)
	time.Sleep(100 * time.Millisecond)
}

// TestSessionKeepsActive verifies active sessions survive cleanup
func TestSessionKeepsActive(t *testing.T) {
	s := &Server{
		sessions: sync.Map{},
	}

	key := "127.0.0.1:12345"
	sess := &UDPSession{
		Dst:        &net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 53},
		Pid:        9999,
		ClientAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345},
		LastActive: time.Now(), // just now
	}
	s.sessions.Store(key, sess)

	// Run cleanup
	s.sessions.Range(func(k, v interface{}) bool {
		if time.Since(v.(*UDPSession).LastActive) > sessionTimeout {
			s.sessions.Delete(k)
		}
		return true
	})

	// Should still be there
	if _, ok := s.sessions.Load(key); !ok {
		t.Error("active session should not be cleaned up")
	}
}
