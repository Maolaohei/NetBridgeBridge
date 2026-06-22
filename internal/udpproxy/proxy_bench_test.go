package udpproxy

import (
	"net"
	"sync"
	"testing"
	"time"
)

func BenchmarkSessionLookup(b *testing.B) {
	s := &Server{
		sessions: sync.Map{},
	}

	for i := 0; i < 1000; i++ {
		key := sessionKey{
			Port: uint16(i),
		}
		s.sessions.Store(key, &UDPSession{
			Dst:        &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: i},
			LastActive: time.Now(),
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := sessionKey{
			Port: uint16(i % 1000),
		}
		s.sessions.Load(key)
	}
}

func BenchmarkSessionStore(b *testing.B) {
	s := &Server{
		sessions: sync.Map{},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := sessionKey{
			Port: uint16(i % 1000),
		}
		s.sessions.Store(key, &UDPSession{
			Dst:        &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: i % 1000},
			LastActive: time.Now(),
		})
	}
}

func BenchmarkBufPool(b *testing.B) {
	pool := sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 65535)
			return &buf
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bufPtr := pool.Get().(*[]byte)
		buf := *bufPtr
		_ = buf[:1024]
		pool.Put(bufPtr)
	}
}

func BenchmarkMakeAlloc(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := make([]byte, 65535)
		_ = buf[:1024]
	}
}

func BenchmarkOldStringKey(b *testing.B) {
	sessions := sync.Map{}

	for i := 0; i < 1000; i++ {
		addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: i}
		sessions.Store(addr.String(), &UDPSession{
			Dst:        addr,
			LastActive: time.Now(),
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: i % 1000}
		sessions.Load(addr.String())
	}
}

func BenchmarkNewStructKey(b *testing.B) {
	s := &Server{
		sessions: sync.Map{},
	}

	for i := 0; i < 1000; i++ {
		key := sessionKey{
			Port: uint16(i),
		}
		s.sessions.Store(key, &UDPSession{
			Dst:        &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: i},
			LastActive: time.Now(),
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := sessionKey{
			Port: uint16(i % 1000),
		}
		s.sessions.Load(key)
	}
}
