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

// pooledConn wraps a net.Conn that has completed SOCKS5 auth negotiation.
// Only CONNECT needs to be sent per request.
type pooledConn struct {
	net.Conn
	createdAt time.Time
}

// ConnPool manages a pool of pre-authenticated SOCKS5 connections to Core.
// Auth negotiation (1 RTT) happens once at creation; only CONNECT is sent per request.
type ConnPool struct {
	coreAddr string
	mu       sync.Mutex
	conns    []pooledConn
	maxSize  int
}

func NewConnPool(coreAddr string, maxSize int) *ConnPool {
	return &ConnPool{
		coreAddr: coreAddr,
		maxSize:  maxSize,
		conns:    make([]pooledConn, 0, maxSize),
	}
}

// createConn establishes a TCP connection and performs SOCKS5 auth negotiation.
func (p *ConnPool) createConn() (pooledConn, error) {
	conn, err := net.DialTimeout("tcp", p.coreAddr, 5*time.Second)
	if err != nil {
		return pooledConn{}, fmt.Errorf("dial core: %w", err)
	}

	// SOCKS5 auth negotiation: no auth
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		conn.Close()
		return pooledConn{}, fmt.Errorf("socks5 auth write: %w", err)
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return pooledConn{}, fmt.Errorf("socks5 auth read: %w", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		conn.Close()
		return pooledConn{}, fmt.Errorf("socks5 auth failed: %x", resp)
	}

	return pooledConn{Conn: conn, createdAt: time.Now()}, nil
}

func (p *ConnPool) Get() (pooledConn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Reuse existing pre-authenticated connection
	for len(p.conns) > 0 {
		pc := p.conns[len(p.conns)-1]
		p.conns = p.conns[:len(p.conns)-1]
		// Reject connections older than 5 minutes (prevent stale auth state)
		if time.Since(pc.createdAt) < 5*time.Minute {
			return pc, nil
		}
		pc.Close()
	}

	// Create new pre-authenticated connection
	return p.createConn()
}

func (p *ConnPool) Put(pc pooledConn) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.conns) < p.maxSize {
		p.conns = append(p.conns, pc)
	} else {
		pc.Close()
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
		pool:  NewConnPool(cfg.CoreSocks, 16),
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

	// Get pre-authenticated connection from pool
	pc, err := s.pool.Get()
	if err != nil {
		s.cfg.Log.Printf("pool.Get: %v", err)
		return
	}

	// SOCKS5 CONNECT to original destination (auth already done)
	dst := hdr.DstHostPort()
	if err := socks5ConnectOnly(pc.Conn, dst); err != nil {
		s.cfg.Log.Printf("socks5 connect to %s: %v", dst, err)
		pc.Close()
		return
	}

	s.cfg.Log.Printf("TCP :%d -> %s (pid=%d proc=%s)",
		hdr.SrcPort, dst, hdr.Pid, hdr.ProcName)

	// Bidirectional relay
	done := make(chan struct{})
	go func() {
		io.Copy(pc.Conn, conn)
		close(done)
	}()
	io.Copy(conn, pc.Conn)
	<-done

	// Return connection to pool for reuse
	s.pool.Put(pc)
}

// socks5ConnectOnly sends SOCKS5 CONNECT on an already auth-negotiated connection.
func socks5ConnectOnly(conn net.Conn, target string) error {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	port, _ := strconv.Atoi(portStr)

	ip := net.ParseIP(host)
	var addrType byte
	var addrBody []byte

	if ip4 := ip.To4(); ip4 != nil {
		addrType = 0x01
		addrBody = ip4
	} else if ip6 := ip.To16(); ip6 != nil {
		addrType = 0x04
		addrBody = ip6
	} else {
		addrType = 0x03
		addrBody = append([]byte{byte(len(host))}, []byte(host)...)
	}

	req := make([]byte, 0, 4+len(addrBody)+2)
	req = append(req, 0x05, 0x01, 0x00, addrType)
	req = append(req, addrBody...)
	req = binary.BigEndian.AppendUint16(req, uint16(port))

	if _, err := conn.Write(req); err != nil {
		return err
	}

	connectResp := make([]byte, 10)
	if _, err := io.ReadFull(conn, connectResp); err != nil {
		return err
	}
	if connectResp[1] != 0x00 {
		return fmt.Errorf("socks5 connect failed: %x", connectResp[1])
	}

	return nil
}
