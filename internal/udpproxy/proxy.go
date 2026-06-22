package udpproxy

import (
	"context"
	"log"
	"net"
	"sync"
	"time"

	"github.com/2dust/netbridge-bridge/internal/protocol"
	"github.com/2dust/netbridge-bridge/internal/security"
)

const (
	sessionTimeout = 60 * time.Second
	cleanupInterval = 10 * time.Second
)

type UDPSession struct {
	Dst        *net.UDPAddr
	Pid        uint32
	ClientAddr *net.UDPAddr // ProxyBridgeCore's loopback socket address
	AddrType   uint8
	LastActive time.Time
}

type Config struct {
	UDPListen string
	CoreSocks string
	Log       *log.Logger
}

type Server struct {
	cfg      Config
	token    uint32
	sessions sync.Map // key: clientAddr.String() → *UDPSession
	conn     *net.UDPConn
}

func NewServer(cfg Config) *Server {
	return &Server{
		cfg:   cfg,
		token: security.GetToken(),
	}
}

func (s *Server) Start(ctx context.Context) error {
	addr, err := net.ResolveUDPAddr("udp4", s.cfg.UDPListen)
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return err
	}
	s.conn = conn

	go func() { <-ctx.Done(); conn.Close() }()
	go s.recvLoop(ctx)
	go s.cleanupLoop(ctx)

	s.cfg.Log.Printf("NetBridge UDP listening on %s", s.cfg.UDPListen)
	return nil
}

func (s *Server) recvLoop(ctx context.Context) {
	buf := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, clientAddr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				s.cfg.Log.Printf("UDP read error: %v", err)
				continue
			}
		}
		if n < protocol.NbUdpReqHeaderSize {
			continue
		}

		// Copy to avoid buffer reuse
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		go s.handlePacket(pkt, clientAddr)
	}
}

func (s *Server) handlePacket(data []byte, clientAddr *net.UDPAddr) {
	// Parse header
	hdr, payload, err := protocol.ParseUdpReqHeader(data)
	if err != nil {
		s.cfg.Log.Printf("parseUdpReqHeader: %v", err)
		return
	}

	if hdr.Magic != protocol.NbMagic {
		return
	}
	if hdr.Version != protocol.NbVersion {
		return
	}
	if hdr.Token != s.token {
		s.cfg.Log.Printf("invalid UDP token from %s", clientAddr)
		return
	}

	// Build destination address
	var dstIP net.IP
	switch hdr.AddrType {
	case protocol.NbAddrIPv4:
		dstIP = make(net.IP, 4)
		copy(dstIP, hdr.DstAddr[:4])
	case protocol.NbAddrIPv6:
		dstIP = make(net.IP, 16)
		copy(dstIP, hdr.DstAddr[:])
	default:
		return
	}
	dst := &net.UDPAddr{IP: dstIP, Port: int(hdr.DstPort)}

	// Session management: use clientAddr as key
	key := clientAddr.String()
	actual, _ := s.sessions.LoadOrStore(key, &UDPSession{
		Dst:        dst,
		Pid:        hdr.Pid,
		ClientAddr: clientAddr,
		AddrType:   hdr.AddrType,
		LastActive: time.Now(),
	})
	sess := actual.(*UDPSession)
	sess.LastActive = time.Now()

	// Forward payload via SOCKS5 UDP to Core
	// For now, send raw payload to Core's UDP port
	// TODO: Implement proper SOCKS5 UDP ASSOCIATE forwarding
	_ = payload
	_ = sess

	s.cfg.Log.Printf("UDP %s -> %s (pid=%d, %d bytes)",
		clientAddr, dst, hdr.Pid, len(payload))
}

func (s *Server) sendReply(clientAddr *net.UDPAddr, srcIP net.IP, srcPort uint16, payload []byte) {
	addrType := uint8(protocol.NbAddrIPv4)
	srcAddrBytes := make([]byte, 16)
	if ip4 := srcIP.To4(); ip4 != nil {
		copy(srcAddrBytes, ip4)
	} else {
		addrType = protocol.NbAddrIPv6
		copy(srcAddrBytes, srcIP.To16())
	}

	hdr := protocol.BuildUdpRespHeader(addrType, srcIP, srcPort, uint16(len(payload)))
	pkt := append(hdr, payload...)
	s.conn.WriteToUDP(pkt, clientAddr)
}

func (s *Server) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sessions.Range(func(k, v interface{}) bool {
				if time.Since(v.(*UDPSession).LastActive) > sessionTimeout {
					s.sessions.Delete(k)
				}
				return true
			})
		}
	}
}
