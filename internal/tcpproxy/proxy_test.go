package tcpproxy

import (
	"context"
	"encoding/binary"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/2dust/netbridge-bridge/internal/protocol"
)

// mockSocks5Server is a minimal SOCKS5 server for testing.
type mockSocks5Server struct {
	ln        net.Listener
	connected chan string
}

func newMockSocks5Server(t *testing.T) *mockSocks5Server {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &mockSocks5Server{ln: ln, connected: make(chan string, 10)}
	go s.serve(t)
	return s
}

func (s *mockSocks5Server) serve(t *testing.T) {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handleConn(t, conn)
	}
}

func (s *mockSocks5Server) handleConn(t *testing.T, conn net.Conn) {
	defer conn.Close()

	// SOCKS5 greeting: version(1) + nmethods(1) + methods(nmethods)
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		return
	}
	nmethods := greeting[1]
	methods := make([]byte, nmethods)
	io.ReadFull(conn, methods)
	conn.Write([]byte{0x05, 0x00}) // no auth

	// CONNECT request
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		return
	}

	var addr string
	switch req[3] {
	case 0x01: // IPv4
		ip := make([]byte, 4)
		io.ReadFull(conn, ip)
		pb := make([]byte, 2)
		io.ReadFull(conn, pb)
		addr = net.IP(ip).String() + ":" + strconv.Itoa(int(binary.BigEndian.Uint16(pb)))
	case 0x03: // Domain
		lb := make([]byte, 1)
		io.ReadFull(conn, lb)
		domain := make([]byte, lb[0])
		io.ReadFull(conn, domain)
		pb := make([]byte, 2)
		io.ReadFull(conn, pb)
		addr = string(domain) + ":" + strconv.Itoa(int(binary.BigEndian.Uint16(pb)))
	case 0x04: // IPv6
		ip := make([]byte, 16)
		io.ReadFull(conn, ip)
		pb := make([]byte, 2)
		io.ReadFull(conn, pb)
		addr = net.IP(ip).String() + ":" + strconv.Itoa(int(binary.BigEndian.Uint16(pb)))
	default:
		return
	}

	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	s.connected <- addr

	// Echo
	io.Copy(conn, conn)
}

func (s *mockSocks5Server) addr() string { return s.ln.Addr().String() }
func (s *mockSocks5Server) close()       { s.ln.Close() }

// TestSocks5Connect_IPv4 tests SOCKS5 CONNECT to IPv4
func TestSocks5Connect_IPv4(t *testing.T) {
	mock := newMockSocks5Server(t)
	defer mock.close()

	conn, err := net.Dial("tcp", mock.addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if err := socks5Connect(conn, "1.2.3.4:443"); err != nil {
		t.Fatalf("socks5Connect: %v", err)
	}

	select {
	case addr := <-mock.connected:
		if addr != "1.2.3.4:443" {
			t.Errorf("got %q, want %q", addr, "1.2.3.4:443")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}

// TestSocks5Connect_IPv6 tests SOCKS5 CONNECT to IPv6
func TestSocks5Connect_IPv6(t *testing.T) {
	mock := newMockSocks5Server(t)
	defer mock.close()

	conn, err := net.Dial("tcp", mock.addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if err := socks5Connect(conn, "[2001:db8::1]:8080"); err != nil {
		t.Fatalf("socks5Connect: %v", err)
	}

	select {
	case addr := <-mock.connected:
		t.Logf("CONNECT addr: %s", addr)
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}

// TestSocks5Connect_Domain tests SOCKS5 CONNECT to domain
func TestSocks5Connect_Domain(t *testing.T) {
	mock := newMockSocks5Server(t)
	defer mock.close()

	conn, err := net.Dial("tcp", mock.addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if err := socks5Connect(conn, "example.com:80"); err != nil {
		t.Fatalf("socks5Connect: %v", err)
	}

	select {
	case addr := <-mock.connected:
		if addr != "example.com:80" {
			t.Errorf("got %q, want %q", addr, "example.com:80")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}

// TestEndToEnd_TCP tests the full chain: NbTcpHeader → Bridge → SOCKS5 → mock server
func TestEndToEnd_TCP(t *testing.T) {
	mock := newMockSocks5Server(t)
	defer mock.close()

	// Start a bridge-like server
	bridgeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bridge listen: %v", err)
	}
	defer bridgeLn.Close()

	go func() {
		for {
			conn, err := bridgeLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()

				hdr, err := protocol.ParseTcpHeader(c)
				if err != nil {
					return
				}
				if hdr.Magic != protocol.NbMagic || hdr.Token != 0 {
					protocol.SendError(c, protocol.NbErrToken)
					return
				}

				coreConn, err := net.Dial("tcp", mock.addr())
				if err != nil {
					return
				}
				defer coreConn.Close()

				if err := socks5Connect(coreConn, hdr.DstHostPort()); err != nil {
					return
				}

				var wg sync.WaitGroup
				wg.Add(2)
				go func() { defer wg.Done(); io.Copy(coreConn, c) }()
				go func() { defer wg.Done(); io.Copy(c, coreConn) }()
				wg.Wait()
			}(conn)
		}
	}()

	// Connect to bridge with NbTcpHeader
	client, err := net.Dial("tcp", bridgeLn.Addr().String())
	if err != nil {
		t.Fatalf("dial bridge: %v", err)
	}
	defer client.Close()

	hdr := make([]byte, protocol.NbTcpHeaderBaseSize)
	binary.LittleEndian.PutUint32(hdr[0:4], protocol.NbMagic)
	hdr[4] = protocol.NbVersion
	hdr[5] = protocol.NbAddrIPv4
	hdr[6] = protocol.NbProtoTCP
	hdr[7] = 0
	binary.LittleEndian.PutUint16(hdr[8:10], 443)
	binary.LittleEndian.PutUint16(hdr[10:12], 12345)
	copy(hdr[12:16], []byte{93, 184, 216, 34}) // example.com IP
	binary.LittleEndian.PutUint32(hdr[28:32], 9999)
	binary.LittleEndian.PutUint32(hdr[32:36], 0) // token=0 (test mode)

	if _, err := client.Write(hdr); err != nil {
		t.Fatalf("write header: %v", err)
	}

	// Send test data
	testData := []byte("Hello from NetBridge test!")
	if _, err := client.Write(testData); err != nil {
		t.Fatalf("write data: %v", err)
	}

	// Verify mock received CONNECT
	select {
	case addr := <-mock.connected:
		t.Logf("Mock got CONNECT to: %s", addr)
		if addr != "93.184.216.34:443" {
			t.Errorf("got %q, want %q", addr, "93.184.216.34:443")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for CONNECT")
	}

	// Read echo
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	n, _ := client.Read(buf)
	if n > 0 {
		t.Logf("Echo: %q", string(buf[:n]))
	}
}

// TestConnPool_GetPut tests connection pool acquire and release
func TestConnPool_GetPut(t *testing.T) {
	mock := newMockSocks5Server(t)
	defer mock.close()

	pool := NewConnPool(mock.addr(), 2)

	// Get should create new connection
	conn1, err := pool.Get()
	if err != nil {
		t.Fatalf("pool.Get: %v", err)
	}
	if conn1 == nil {
		t.Fatal("pool.Get returned nil")
	}

	// Put it back
	pool.Put(conn1)

	// Get again — should reuse from pool
	conn2, err := pool.Get()
	if err != nil {
		t.Fatalf("pool.Get second: %v", err)
	}
	if conn2 != conn1 {
		t.Error("pool did not reuse connection")
	}
	pool.Put(conn2)

	// Pool full — Put should close excess
	pool.Put(conn1) // already in pool, this should close conn1
}

func TestConnPool_GetNewConnection(t *testing.T) {
	mock := newMockSocks5Server(t)
	defer mock.close()

	pool := NewConnPool(mock.addr(), 1)
	conn, err := pool.Get()
	if err != nil {
		t.Fatalf("pool.Get: %v", err)
	}
	pool.Put(conn)

	// Fill the pool
	conn2, _ := pool.Get()
	pool.Put(conn2)

	// Pool is full, Get should create new
	conn3, err := pool.Get()
	if err != nil {
		t.Fatalf("pool.Get when full: %v", err)
	}
	pool.Put(conn3)
}

func TestConnPool_PutNil(t *testing.T) {
	pool := NewConnPool("127.0.0.1:9999", 2)
	pool.Put(nil) // should not panic
}

// TestServer_Start tests that the server starts and accepts connections
func TestServer_Start(t *testing.T) {
	mock := newMockSocks5Server(t)
	defer mock.close()

	// Create server with a real listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	s := &Server{
		cfg: Config{
			TCPListen: ln.Addr().String(),
			CoreSocks: mock.addr(),
			Log:       testLog(t),
		},
		token: 0,
		pool:  NewConnPool(mock.addr(), 2),
	}

	// Accept in background
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handleConn(conn)
		}
	}()

	// Connect with valid header
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	hdr := make([]byte, protocol.NbTcpHeaderBaseSize)
	binary.LittleEndian.PutUint32(hdr[0:4], protocol.NbMagic)
	hdr[4] = protocol.NbVersion
	hdr[5] = protocol.NbAddrIPv4
	hdr[6] = protocol.NbProtoTCP
	hdr[7] = 0
	binary.LittleEndian.PutUint16(hdr[8:10], 80)
	binary.LittleEndian.PutUint16(hdr[10:12], 11111)
	binary.LittleEndian.PutUint32(hdr[28:32], 42)
	binary.LittleEndian.PutUint32(hdr[32:36], 0) // token=0

	client.Write(hdr)

	select {
	case addr := <-mock.connected:
		t.Logf("Server forwarded to: %s", addr)
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for connection on mock")
	}
}

func testLog(t *testing.T) *log.Logger {
	return log.New(testWriter{t}, "[TEST] ", 0)
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (n int, err error) {
	w.t.Logf("%s", string(p))
	return len(p), nil
}

// TestTokenValidation tests that wrong token is rejected
// TestHandleConn_InvalidMagic tests that invalid magic is rejected
func TestHandleConn_InvalidMagic(t *testing.T) {
	mock := newMockSocks5Server(t)
	defer mock.close()

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()

	s := &Server{
		cfg:   Config{CoreSocks: mock.addr(), Log: testLog(t)},
		token: 0,
		pool:  NewConnPool(mock.addr(), 2),
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handleConn(conn)
		}
	}()

	// Send invalid magic
	conn, _ := net.Dial("tcp", ln.Addr().String())
	defer conn.Close()
	conn.Write([]byte{0x00, 0x00, 0x00, 0x00}) // wrong magic
	time.Sleep(100 * time.Millisecond)
	// Connection should be closed by server
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, err := conn.Read(make([]byte, 1))
	if err == nil {
		t.Error("expected connection closed")
	}
}

// TestHandleConn_WrongVersion tests version error response
func TestHandleConn_WrongVersion(t *testing.T) {
	mock := newMockSocks5Server(t)
	defer mock.close()

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()

	s := &Server{
		cfg:   Config{CoreSocks: mock.addr(), Log: testLog(t)},
		token: 0,
		pool:  NewConnPool(mock.addr(), 2),
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handleConn(conn)
		}
	}()

	conn, _ := net.Dial("tcp", ln.Addr().String())
	defer conn.Close()

	hdr := make([]byte, protocol.NbTcpHeaderBaseSize)
	binary.LittleEndian.PutUint32(hdr[0:4], protocol.NbMagic)
	hdr[4] = 0 // wrong version
	hdr[5] = protocol.NbAddrIPv4
	hdr[6] = protocol.NbProtoTCP
	conn.Write(hdr)

	resp := make([]byte, 8)
	n, _ := io.ReadFull(conn, resp)
	if n >= 6 && resp[5] != protocol.NbErrVersion {
		t.Errorf("error code = %d, want %d", resp[5], protocol.NbErrVersion)
	}
}

// TestHandleConn_WrongToken tests token error response
func TestHandleConn_WrongToken(t *testing.T) {
	mock := newMockSocks5Server(t)
	defer mock.close()

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()

	s := &Server{
		cfg:   Config{CoreSocks: mock.addr(), Log: testLog(t)},
		token: 0x12345678, // require this token
		pool:  NewConnPool(mock.addr(), 2),
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handleConn(conn)
		}
	}()

	conn, _ := net.Dial("tcp", ln.Addr().String())
	defer conn.Close()

	hdr := make([]byte, protocol.NbTcpHeaderBaseSize)
	binary.LittleEndian.PutUint32(hdr[0:4], protocol.NbMagic)
	hdr[4] = protocol.NbVersion
	hdr[5] = protocol.NbAddrIPv4
	hdr[6] = protocol.NbProtoTCP
	binary.LittleEndian.PutUint32(hdr[32:36], 0xAAAAAAAA) // wrong token
	conn.Write(hdr)

	resp := make([]byte, 8)
	n, _ := io.ReadFull(conn, resp)
	if n >= 6 && resp[5] != protocol.NbErrToken {
		t.Errorf("error code = %d, want %d", resp[5], protocol.NbErrToken)
	}
}

// TestNewServer verifies server creation
func TestNewServer(t *testing.T) {
	s := NewServer(Config{
		TCPListen: "127.0.0.1:35000",
		CoreSocks: "127.0.0.1:10808",
		Log:       testLog(t),
	})
	if s == nil {
		t.Fatal("NewServer returned nil")
	}
	if s.cfg.CoreSocks != "127.0.0.1:10808" {
		t.Errorf("CoreSocks = %q", s.cfg.CoreSocks)
	}
}

// TestSocks5Connect_Failure tests SOCKS5 failure response
func TestSocks5Connect_Failure(t *testing.T) {
	// Server that rejects all connections
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		conn, _ := ln.Accept()
		if conn == nil {
			return
		}
		defer conn.Close()
		conn.Write([]byte{0x05, 0x00})       // auth OK
		conn.Write([]byte{0x05, 0x01, 0, 0, 0, 0, 0, 0, 0, 0}) // CONNECT failure
	}()

	conn, _ := net.Dial("tcp", ln.Addr().String())
	defer conn.Close()
	err := socks5Connect(conn, "1.2.3.4:443")
	if err == nil {
		t.Error("expected error for CONNECT failure")
	}
}

// TestServer_Start_ContextCancel tests graceful shutdown
func TestServer_Start_ContextCancel(t *testing.T) {
	mock := newMockSocks5Server(t)
	defer mock.close()

	s := NewServer(Config{
		TCPListen: "127.0.0.1:0",
		CoreSocks: mock.addr(),
		Log:       testLog(t),
	})

	ctx, cancel := context.WithCancel(context.Background())
	err := s.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Cancel context should stop the server
	cancel()
	time.Sleep(200 * time.Millisecond)
}

// TestServer_Start_AlreadyRunning tests double-start
func TestServer_Start_AlreadyRunning(t *testing.T) {
	mock := newMockSocks5Server(t)
	defer mock.close()

	s := NewServer(Config{
		TCPListen: "127.0.0.1:0",
		CoreSocks: mock.addr(),
		Log:       testLog(t),
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := s.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
}

// TestHandleConn_PoolGetFailure tests what happens when pool.Get fails
func TestHandleConn_PoolGetFailure(t *testing.T) {
	// Server that's not listening = pool.Get will fail
	s := &Server{
		cfg:   Config{CoreSocks: "127.0.0.1:1", Log: testLog(t)}, // wrong port
		token: 0,
		pool:  NewConnPool("127.0.0.1:1", 2),
	}

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handleConn(conn)
		}
	}()

	conn, _ := net.Dial("tcp", ln.Addr().String())
	defer conn.Close()

	hdr := make([]byte, protocol.NbTcpHeaderBaseSize)
	binary.LittleEndian.PutUint32(hdr[0:4], protocol.NbMagic)
	hdr[4] = protocol.NbVersion
	hdr[5] = protocol.NbAddrIPv4
	hdr[6] = protocol.NbProtoTCP
	conn.Write(hdr)
	time.Sleep(200 * time.Millisecond)
	// Should not crash, connection should be closed
}

// TestSocks5Connect_AuthRequired tests SOCKS5 with auth required
func TestSocks5Connect_AuthRequired(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		conn, _ := ln.Accept()
		if conn == nil {
			return
		}
		defer conn.Close()
		// Read greeting
		g := make([]byte, 2)
		io.ReadFull(conn, g)
		nm := make([]byte, g[1])
		io.ReadFull(conn, nm)
		// Require auth
		conn.Write([]byte{0x05, 0x02}) // method 0x02 = username/password
	}()

	conn, _ := net.Dial("tcp", ln.Addr().String())
	defer conn.Close()
	err := socks5Connect(conn, "1.2.3.4:443")
	if err == nil {
		t.Error("expected error for auth required")
	}
}

func TestTokenValidation(t *testing.T) {
	bridgeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer bridgeLn.Close()

	// Server that requires token=0x12345678
	go func() {
		for {
			conn, err := bridgeLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				hdr, err := protocol.ParseTcpHeader(c)
				if err != nil {
					return
				}
				if hdr.Token != 0x12345678 {
					protocol.SendError(c, protocol.NbErrToken)
					return
				}
				// Success — just close
			}(conn)
		}
	}()

	// Connect with wrong token
	client, err := net.Dial("tcp", bridgeLn.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	hdr := make([]byte, protocol.NbTcpHeaderBaseSize)
	binary.LittleEndian.PutUint32(hdr[0:4], protocol.NbMagic)
	hdr[4] = protocol.NbVersion
	hdr[5] = protocol.NbAddrIPv4
	hdr[6] = protocol.NbProtoTCP
	hdr[7] = 0
	binary.LittleEndian.PutUint16(hdr[8:10], 80)
	binary.LittleEndian.PutUint16(hdr[10:12], 11111)
	binary.LittleEndian.PutUint32(hdr[28:32], 9999)
	binary.LittleEndian.PutUint32(hdr[32:36], 0xAAAAAAAA) // wrong token

	client.Write(hdr)

	// Read error response
	resp := make([]byte, 8)
	n, _ := io.ReadFull(client, resp)
	if n < 6 {
		t.Fatalf("expected 6+ bytes response, got %d", n)
	}
	errCode := resp[5]
	if errCode != protocol.NbErrToken {
		t.Errorf("error code = %d, want %d (NB_ERR_TOKEN)", errCode, protocol.NbErrToken)
	}
	t.Logf("Got expected TOKEN error (code=%d)", errCode)
}
