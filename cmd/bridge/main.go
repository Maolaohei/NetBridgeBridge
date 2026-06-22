package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/2dust/netbridge-bridge/internal/security"
	"github.com/2dust/netbridge-bridge/internal/tcpproxy"
	"github.com/2dust/netbridge-bridge/internal/udpproxy"
)

const (
	defaultTCPListen = "127.0.0.1:35000"
	defaultUDPListen = "127.0.0.1:35001"
	defaultCoreSocks = "127.0.0.1:10808"
)

func main() {
	tcpListen := flag.String("tcp-listen", defaultTCPListen, "TCP listen address")
	udpListen := flag.String("udp-listen", defaultUDPListen, "UDP listen address")
	coreSocks := flag.String("core-socks", defaultCoreSocks, "Core SOCKS5 address")
	flag.Parse()

	logger := log.New(os.Stderr, "[NetBridge] ", log.LstdFlags)

	// Read token from Named Shared Memory
	if err := security.InitToken(); err != nil {
		logger.Printf("WARNING: Token init failed: %v (proceeding without auth)", err)
	} else {
		logger.Printf("Token loaded: 0x%08X", security.GetToken())
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start TCP proxy
	tcpSrv := tcpproxy.NewServer(tcpproxy.Config{
		TCPListen: *tcpListen,
		CoreSocks: *coreSocks,
		Log:       logger,
	})
	if err := tcpSrv.Start(ctx); err != nil {
		logger.Fatalf("TCP server: %v", err)
	}

	// Start UDP proxy
	udpSrv := udpproxy.NewServer(udpproxy.Config{
		UDPListen: *udpListen,
		CoreSocks: *coreSocks,
		Log:       logger,
	})
	if err := udpSrv.Start(ctx); err != nil {
		logger.Fatalf("UDP server: %v", err)
	}

	logger.Printf("NetBridge Bridge started")
	logger.Printf("  TCP: %s -> %s", *tcpListen, *coreSocks)
	logger.Printf("  UDP: %s -> %s", *udpListen, *coreSocks)

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	logger.Printf("Shutting down...")
	cancel()
}
