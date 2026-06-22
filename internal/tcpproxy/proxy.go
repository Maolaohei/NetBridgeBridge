package tcpproxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/2dust/netbridge-bridge/internal/protocol"
	"github.com/2dust/netbridge-bridge/internal/security"
)

type Config struct {
	TCPListen string
	CoreSocks string
	Log       *log.Logger
}

// ConnPool manages a pool of pre-established SOCKS5 connections to Core.
type ConnPool struct {
	coreAddr string
	mu       sync.Mutex
	conns    []net.Conn
	maxSize  int
}

func NewConnPool(coreAddr string, maxSize int) *ConnPool {
	return &ConnPool{
		coreAddr: coreAddr,
		maxSize:  maxSize,
		conns:    make([]net.Conn, 0, maxSize),
	}
}

func (p *ConnPool) Get() (net.Conn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.conns) > 0 {
		conn := p.conns[len(p.conns)-1]
		p.conns = p.conns[:len(p.conns)-1]
		// Verify connection is still alive
		if conn != nil {
			return conn, nil
		}
	}

	// Create new connection
	conn, err := net.DialTimeout("tcp", p.coreAddr, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial core: %w", err)
	}
	return conn, nil
}

func (p *ConnPool) Put(conn net.Conn) {
	if conn == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.conns) < p.maxSize {
		p.conns = append(p.conns, conn)
	} else {
		conn.Close()
	}
}

type Server struct {
	cfg    Config
	token  uint32
	pool   *ConnPool
}

func NewServer(cfg Config) *Server {
	return &Server{
		cfg:   cfg,
		token: security.GetToken(),
		pool:  NewConnPool(cfg.CoreSocks, 8),
	}
}

func (s *Server) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.TCPListen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.cfg.TCPListen, err)
	}

	go func() { <-ctx.Done(); ln.Close() }()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					s.cfg.Log.Printf("accept error: %v", err)
					continue
				}
			}
			go s.handleConn(conn)
		}
	}()

	s.cfg.Log.Printf("NetBridge TCP listening on %s", s.cfg.TCPListen)
	return nil
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()

	hdr, err := protocol.ParseTcpHeader(conn)
	if err != nil {
		s.cfg.Log.Printf("parseTcpHeader: %v", err)
		return
	}

	if hdr.Magic != protocol.NbMagic {
		s.cfg.Log.Printf("invalid magic 0x%08X", hdr.Magic)
		return
	}
	if hdr.Version != protocol.NbVersion {
		protocol.SendError(conn, protocol.NbErrVersion)
		return
	}
	if hdr.Token != s.token {
		s.cfg.Log.Printf("invalid token from pid %d proc %s", hdr.Pid, hdr.ProcName)
		protocol.SendError(conn, protocol.NbErrToken)
		return
	}

	// Get connection from pool
	coreConn, err := s.pool.Get()
	if err != nil {
		s.cfg.Log.Printf("pool.Get: %v", err)
		return
	}

	// SOCKS5 CONNECT to original destination
	dst := hdr.DstHostPort()
	if err := socks5Connect(coreConn, dst); err != nil {
		s.cfg.Log.Printf("socks5 connect to %s: %v", dst, err)
		coreConn.Close()
		return
	}

	s.cfg.Log.Printf("TCP %s:%d -> %s (pid=%d proc=%s)",
		hdr.DstAddr[:4], hdr.DstPort, dst, hdr.Pid, hdr.ProcName)

	// Bidirectional relay
	done := make(chan struct{})
	go func() {
		io.Copy(coreConn, conn)
		close(done)
	}()
	io.Copy(conn, coreConn)
	<-done

	coreConn.Close()
}

// socks5Connect performs SOCKS5 handshake + CONNECT to target.
func socks5Connect(conn net.Conn, target string) error {
	// Auth negotiation: no auth
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return err
	}

	// Read server response
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		return fmt.Errorf("socks5 auth failed: %x", resp)
	}

	// Parse target address
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	port, _ := strconv.Atoi(portStr)

	ip := net.ParseIP(host)
	var addrType byte
	var addrBody []byte

	if ip4 := ip.To4(); ip4 != nil {
		addrType = 0x01 // IPv4
		addrBody = ip4
	} else if ip6 := ip.To16(); ip6 != nil {
		addrType = 0x04 // IPv6
		addrBody = ip6
	} else {
		// Domain name
		addrType = 0x03
		addrBody = append([]byte{byte(len(host))}, []byte(host)...)
	}

	// SOCKS5 CONNECT request
	req := make([]byte, 0, 4+len(addrBody)+2)
	req = append(req, 0x05, 0x01, 0x00, addrType)
	req = append(req, addrBody...)
	req = binary.BigEndian.AppendUint16(req, uint16(port))

	if _, err := conn.Write(req); err != nil {
		return err
	}

	// Read CONNECT response
	connectResp := make([]byte, 10)
	if _, err := io.ReadFull(conn, connectResp); err != nil {
		return err
	}
	if connectResp[1] != 0x00 {
		return fmt.Errorf("socks5 connect failed: %x", connectResp[1])
	}

	return nil
}
