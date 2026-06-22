package udpproxy

import (
	"context"
	"encoding/binary"
	"log"
	"net"
	"sync"
	"time"

	"github.com/2dust/netbridge-bridge/internal/protocol"
	"github.com/2dust/netbridge-bridge/internal/security"
)

const (
	sessionTimeout    = 60 * time.Second
	dnsSessionTimeout = 10 * time.Second
	cleanupInterval   = 10 * time.Second
	bufPoolSize       = 64
)

type UDPSession struct {
	Dst        *net.UDPAddr
	Pid        uint32
	ClientAddr *net.UDPAddr
	AddrType   uint8
	LastActive time.Time
	IsDNS      bool
}

type sessionKey struct {
	IP   [16]byte
	Port uint16
}

type Config struct {
	UDPListen string
	CoreSocks string
	Log       *log.Logger
}

type Server struct {
	cfg      Config
	token    uint32
	sessions sync.Map
	conn     *net.UDPConn
	bufPool  sync.Pool
}

func NewServer(cfg Config) *Server {
	return &Server{
		cfg:   cfg,
		token: security.GetToken(),
		bufPool: sync.Pool{
			New: func() interface{} {
				buf := make([]byte, 65535)
				return &buf
			},
		},
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
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		bufPtr := s.bufPool.Get().(*[]byte)
		buf := *bufPtr

		n, clientAddr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			s.bufPool.Put(bufPtr)
			select {
			case <-ctx.Done():
				return
			default:
				s.cfg.Log.Printf("UDP read error: %v", err)
				continue
			}
		}
		if n < protocol.NbUdpReqHeaderSize {
			s.bufPool.Put(bufPtr)
			continue
		}

		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		s.bufPool.Put(bufPtr)

		go s.handlePacket(pkt, clientAddr)
	}
}

func (s *Server) handlePacket(data []byte, clientAddr *net.UDPAddr) {
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

	var key sessionKey
	copy(key.IP[:], hdr.DstAddr[:])
	key.Port = hdr.DstPort

	isDNS := hdr.DstPort == 53

	now := time.Now()
	if actual, loaded := s.sessions.Load(key); loaded {
		sess := actual.(*UDPSession)
		sess.LastActive = now
		sess.Dst = dst
	} else {
		s.sessions.Store(key, &UDPSession{
			Dst:        dst,
			Pid:        hdr.Pid,
			ClientAddr: clientAddr,
			AddrType:   hdr.AddrType,
			LastActive: now,
			IsDNS:      isDNS,
		})
	}

	s.cfg.Log.Printf("UDP %s -> %s (pid=%d, %d bytes)",
		clientAddr, dst, hdr.Pid, len(payload))

	_ = payload
}

func (s *Server) sendReply(clientAddr *net.UDPAddr, srcIP net.IP, srcPort uint16, payload []byte) {
	addrType := protocol.NbAddrIPv4
	if ip4 := srcIP.To4(); ip4 == nil {
		addrType = protocol.NbAddrIPv6
	}

	hdr := protocol.BuildUdpRespHeader(addrType, srcIP, srcPort, uint16(len(payload)))

	var buf []byte
	if s.bufPool.New != nil {
		bufPtr := s.bufPool.Get().(*[]byte)
		buf = *bufPtr
		copy(buf, hdr)
		copy(buf[len(hdr):], payload)
		s.conn.WriteToUDP(buf[:len(hdr)+len(payload)], clientAddr)
		s.bufPool.Put(bufPtr)
	} else {
		buf = append(hdr, payload...)
		s.conn.WriteToUDP(buf, clientAddr)
	}
}

func (s *Server) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			s.sessions.Range(func(k, v interface{}) bool {
				sess := v.(*UDPSession)
				timeout := sessionTimeout
				if sess.IsDNS {
					timeout = dnsSessionTimeout
				}
				if now.Sub(sess.LastActive) > timeout {
					s.sessions.Delete(k)
				}
				return true
			})
		}
	}
}

func sessionKeyFromAddr(addr *net.UDPAddr) sessionKey {
	var key sessionKey
	if ip4 := addr.IP.To4(); ip4 != nil {
		copy(key.IP[:4], ip4)
	} else {
		copy(key.IP[:], addr.IP.To16())
	}
	key.Port = uint16(addr.Port)
	return key
}

func (s *Server) findSessionByClient(clientAddr *net.UDPAddr) *UDPSession {
	var result *UDPSession
	s.sessions.Range(func(k, v interface{}) bool {
		sess := v.(*UDPSession)
		if sess.ClientAddr.IP.Equal(clientAddr.IP) && sess.ClientAddr.Port == clientAddr.Port {
			result = sess
			return false
		}
		return true
	})
	return result
}

func buildNbUdpHeader(addrType uint8, dstIP net.IP, dstPort uint16, pid uint32, token uint32) []byte {
	hdr := make([]byte, protocol.NbUdpReqHeaderSize)
	binary.LittleEndian.PutUint32(hdr[0:4], protocol.NbMagic)
	hdr[4] = protocol.NbVersion
	hdr[5] = addrType
	hdr[6] = protocol.NbProtoUDP

	binary.LittleEndian.PutUint16(hdr[8:10], dstPort)

	if addrType == protocol.NbAddrIPv4 {
		if ip4 := dstIP.To4(); ip4 != nil {
			copy(hdr[12:16], ip4)
		}
	} else {
		copy(hdr[12:28], dstIP.To16())
	}

	binary.LittleEndian.PutUint32(hdr[44:48], pid)
	binary.LittleEndian.PutUint32(hdr[48:52], token)

	return hdr
}
