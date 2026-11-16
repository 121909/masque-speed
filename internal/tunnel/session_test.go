package tunnel

import (
	"context"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"fofa-masque/internal/model"
)

func loopbackEndpoint(t *testing.T, address string) model.Endpoint {
	t.Helper()
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	return model.Endpoint{IP: host, Port: n}
}

func TestTCPStalledTLSCancellation(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan struct{})
	peerDone := make(chan struct{})
	go func() {
		defer close(peerDone)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		close(accepted)
		// Read the client's TLS bytes but never send a TLS response.
		_, _ = io.Copy(io.Discard, conn)
	}()
	c, err := parseCredentials(testCredentials(t))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := newSession(ctx)
	done := make(chan error, 1)
	go func() {
		err := s.connect(loopbackEndpoint(t, listener.Addr().String()), "tcp", c, "test.invalid", 5*time.Second)
		s.Close()
		done <- err
	}()
	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("TCP connection was not accepted")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("stalled TLS handshake succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("TLS cancellation or session cleanup blocked")
	}
	select {
	case <-peerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("outer TCP connection remained open")
	}
}

func TestUDPHandshakeTimeout(t *testing.T) {
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	peerDone := make(chan struct{})
	received := make(chan struct{}, 1)
	go func() {
		defer close(peerDone)
		buffer := make([]byte, 2048)
		for {
			if _, _, err := peer.ReadFromUDP(buffer); err != nil {
				return
			}
			select {
			case received <- struct{}{}:
			default:
			}
		}
	}()
	defer func() {
		_ = peer.Close()
		select {
		case <-peerDone:
		case <-time.After(2 * time.Second):
			t.Error("UDP peer did not stop")
		}
	}()
	c, err := parseCredentials(testCredentials(t))
	if err != nil {
		t.Fatal(err)
	}
	s := newSession(context.Background())
	done := make(chan error, 1)
	go func() {
		err := s.connect(loopbackEndpoint(t, peer.LocalAddr().String()), "udp", c, "test.invalid", 100*time.Millisecond)
		s.Close()
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("unresponsive QUIC endpoint succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("QUIC timeout or session cleanup blocked")
	}
	select {
	case <-received:
	default:
		t.Fatal("QUIC handshake sent no packet to the selected endpoint")
	}
}
