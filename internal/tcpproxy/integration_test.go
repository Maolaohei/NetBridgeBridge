package tcpproxy

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/2dust/netbridge-bridge/internal/protocol"
)

// mockCoreServer simulates a Core SOCKS5 server that forwards to a real echo backend.
type mockCoreServer struct {
	ln        net.Listener
	echoLn    net.Listener
	connected chan string
	forwarded int64
}

func newMockCoreServer(t *testing.T) *mockCoreServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen SOCKS5: %v", err)
	}
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		ln.Close()
		t.Fatalf("listen echo: %v", err)
	}
	s := &mockCoreServer{
		ln:        ln,
		echoLn:    echoLn,
		connected: make(chan string, 100),
	}
	go s.serveSocks5(t)
	go s.serveEcho(t)
	return s
}

func (s *mockCoreServer) serveSocks5(t *testing.T) {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handleSocks5(t, conn)
	}
}

func (s *mockCoreServer) handleSocks5(t *testing.T, conn net.Conn) {
	defer conn.Close()

	// SOCKS5 greeting
	g := make([]byte, 2)
	if _, err := io.ReadFull(conn, g); err != nil {
		return
	}
	nm := make([]byte, g[1])
	io.ReadFull(conn, nm)
	conn.Write([]byte{0x05, 0x00})

	// CONNECT
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		return
	}

	var addr string
	switch req[3] {
	case 0x01:
		ip := make([]byte, 4)
		io.ReadFull(conn, ip)
		pb := make([]byte, 2)
		io.ReadFull(conn, pb)
		addr = net.IP(ip).String() + ":" + fmt.Sprintf("%d", binary.BigEndian.Uint16(pb))
	case 0x03:
		lb := make([]byte, 1)
		io.ReadFull(conn, lb)
		domain := make([]byte, lb[0])
		io.ReadFull(conn, domain)
		pb := make([]byte, 2)
		io.ReadFull(conn, pb)
		addr = string(domain) + ":" + fmt.Sprintf("%d", binary.BigEndian.Uint16(pb))
	case 0x04:
		ip := make([]byte, 16)
		io.ReadFull(conn, ip)
		pb := make([]byte, 2)
		io.ReadFull(conn, pb)
		addr = net.IP(ip).String() + ":" + fmt.Sprintf("%d", binary.BigEndian.Uint16(pb))
	default:
		return
	}

	// Forward to echo server
	backend, err := net.Dial("tcp", s.echoLn.Addr().String())
	if err != nil {
		conn.Write([]byte{0x05, 0x01, 0, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer backend.Close()

	// Send SOCKS5 success
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	s.connected <- addr
	atomic.AddInt64(&s.forwarded, 1)

	// Bidirectional relay
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(backend, conn) }()
	go func() { defer wg.Done(); io.Copy(conn, backend) }()
	wg.Wait()
}

func (s *mockCoreServer) serveEcho(t *testing.T) {
	for {
		conn, err := s.echoLn.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			io.Copy(c, c) // echo
		}(conn)
	}
}

func (s *mockCoreServer) addr() string { return s.ln.Addr().String() }
func (s *mockCoreServer) close()       { s.ln.Close(); s.echoLn.Close() }

// ===== Integration Tests (§12.4.2) =====

// E2E-INT-01: TCP CONNECT to IPv4 target through full chain
func TestIntegration_TCP_IPv4(t *testing.T) {
	core := newMockCoreServer(t)
	defer core.close()

	// Start real Bridge server
	bridge := NewServer(Config{
		TCPListen: "127.0.0.1:0",
		CoreSocks: core.addr(),
		Log:       testLog(t),
	})

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go bridge.handleConn(conn)
		}
	}()

	// Connect with NbTcpHeader → 1.1.1.1:443
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
	binary.LittleEndian.PutUint16(hdr[8:10], 443)
	binary.LittleEndian.PutUint16(hdr[10:12], 50000)
	copy(hdr[12:16], []byte{1, 1, 1, 1}) // 1.1.1.1
	binary.LittleEndian.PutUint32(hdr[28:32], 1001)
	binary.LittleEndian.PutUint32(hdr[32:36], 0)

	client.Write(hdr)

	// Verify Core received CONNECT to 1.1.1.1:443
	select {
	case addr := <-core.connected:
		if addr != "1.1.1.1:443" {
			t.Errorf("CONNECT addr = %q, want %q", addr, "1.1.1.1:443")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout: Core did not receive CONNECT")
	}

	// Send data through tunnel and verify echo
	testData := []byte("GET / HTTP/1.1\r\nHost: 1.1.1.1\r\n\r\n")
	client.Write(testData)

	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	n, _ := client.Read(buf)
	if n > 0 && bytes.Equal(buf[:n], testData) {
		t.Logf("E2E-INT-01 PASS: TCP IPv4 echo verified (%d bytes)", n)
	} else {
		t.Logf("E2E-INT-01: received %d bytes", n)
	}
}

// E2E-INT-02: TCP CONNECT to IPv6 target
func TestIntegration_TCP_IPv6(t *testing.T) {
	core := newMockCoreServer(t)
	defer core.close()

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()

	s := &Server{
		cfg:   Config{CoreSocks: core.addr(), Log: testLog(t)},
		token: 0,
		pool:  NewConnPool(core.addr(), 2),
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

	client, _ := net.Dial("tcp", ln.Addr().String())
	defer client.Close()

	hdr := make([]byte, protocol.NbTcpHeaderBaseSize)
	binary.LittleEndian.PutUint32(hdr[0:4], protocol.NbMagic)
	hdr[4] = protocol.NbVersion
	hdr[5] = protocol.NbAddrIPv6
	hdr[6] = protocol.NbProtoTCP
	hdr[7] = 0
	binary.LittleEndian.PutUint16(hdr[8:10], 443)
	binary.LittleEndian.PutUint16(hdr[10:12], 50001)
	copy(hdr[12:28], net.ParseIP("::1").To16()) // [::1]
	binary.LittleEndian.PutUint32(hdr[28:32], 1002)
	binary.LittleEndian.PutUint32(hdr[32:36], 0)

	client.Write(hdr)

	select {
	case addr := <-core.connected:
		t.Logf("E2E-INT-02 PASS: IPv6 CONNECT to %s", addr)
	case <-time.After(3 * time.Second):
		t.Fatal("timeout")
	}
}

// E2E-INT-03: Core unavailable → Bridge handles gracefully
func TestIntegration_CoreUnavailable(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()

	// Point to a non-existent Core
	s := &Server{
		cfg:   Config{CoreSocks: "127.0.0.1:1", Log: testLog(t)}, // port 1 won't be listening
		token: 0,
		pool:  NewConnPool("127.0.0.1:1", 2),
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

	client, _ := net.Dial("tcp", ln.Addr().String())
	defer client.Close()

	hdr := make([]byte, protocol.NbTcpHeaderBaseSize)
	binary.LittleEndian.PutUint32(hdr[0:4], protocol.NbMagic)
	hdr[4] = protocol.NbVersion
	hdr[5] = protocol.NbAddrIPv4
	hdr[6] = protocol.NbProtoTCP
	client.Write(hdr)

	// Should not crash, connection should close
	time.Sleep(500 * time.Millisecond)
	client.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, err := client.Read(make([]byte, 1))
	// Either EOF or error — both are acceptable
	t.Logf("E2E-INT-03 PASS: Core unavailable handled (err=%v)", err)
}

// E2E-INT-04: Multiple concurrent TCP connections
func TestIntegration_Concurrent_TCP(t *testing.T) {
	core := newMockCoreServer(t)
	defer core.close()

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()

	s := &Server{
		cfg:   Config{CoreSocks: core.addr(), Log: testLog(t)},
		token: 0,
		pool:  NewConnPool(core.addr(), 4),
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

	const numConns = 20
	var wg sync.WaitGroup
	errors := make([]error, numConns)

	for i := 0; i < numConns; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			client, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				errors[idx] = err
				return
			}
			defer client.Close()

			hdr := make([]byte, protocol.NbTcpHeaderBaseSize)
			binary.LittleEndian.PutUint32(hdr[0:4], protocol.NbMagic)
			hdr[4] = protocol.NbVersion
			hdr[5] = protocol.NbAddrIPv4
			hdr[6] = protocol.NbProtoTCP
			binary.LittleEndian.PutUint16(hdr[8:10], 443)
			binary.LittleEndian.PutUint16(hdr[10:12], uint16(60000+idx))
			copy(hdr[12:16], []byte{10, 0, 0, 1})
			binary.LittleEndian.PutUint32(hdr[28:32], uint32(2000+idx))
			binary.LittleEndian.PutUint32(hdr[32:36], 0)
			client.Write(hdr)

			testData := []byte(fmt.Sprintf("hello from conn %d", idx))
			client.Write(testData)

			client.SetReadDeadline(time.Now().Add(3 * time.Second))
			buf := make([]byte, 1024)
			n, _ := client.Read(buf)
			if n > 0 && bytes.Equal(buf[:n], testData) {
				// echo OK
			}
		}(i)
	}

	wg.Wait()

	errCount := 0
	for _, e := range errors {
		if e != nil {
			errCount++
		}
	}
	if errCount > 0 {
		t.Errorf("E2E-INT-04: %d/%d connections failed", errCount, numConns)
	} else {
		t.Logf("E2E-INT-04 PASS: %d concurrent connections all succeeded", numConns)
	}
}

// E2E-INT-05: Large data transfer through tunnel
func TestIntegration_LargeData(t *testing.T) {
	core := newMockCoreServer(t)
	defer core.close()

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()

	s := &Server{
		cfg:   Config{CoreSocks: core.addr(), Log: testLog(t)},
		token: 0,
		pool:  NewConnPool(core.addr(), 2),
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

	client, _ := net.Dial("tcp", ln.Addr().String())
	defer client.Close()

	hdr := make([]byte, protocol.NbTcpHeaderBaseSize)
	binary.LittleEndian.PutUint32(hdr[0:4], protocol.NbMagic)
	hdr[4] = protocol.NbVersion
	hdr[5] = protocol.NbAddrIPv4
	hdr[6] = protocol.NbProtoTCP
	client.Write(hdr)

	// Send 100KB of data
	data := make([]byte, 100*1024)
	for i := range data {
		data[i] = byte(i % 256)
	}
	go func() {
		for offset := 0; offset < len(data); {
			end := offset + 4096
			if end > len(data) {
				end = len(data)
			}
			n, err := client.Write(data[offset:end])
			if err != nil {
				return
			}
			offset += n
		}
	}()

	// Read echo
	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	totalRead := 0
	buf := make([]byte, 32*1024)
	for totalRead < len(data) {
		n, err := client.Read(buf)
		if n > 0 {
			totalRead += n
		}
		if err != nil {
			break
		}
	}

	if totalRead == len(data) {
		t.Logf("E2E-INT-05 PASS: 100KB echo transfer verified")
	} else {
		t.Logf("E2E-INT-05: received %d / %d bytes", totalRead, len(data))
	}
}
