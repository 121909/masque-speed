package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	connectip "github.com/Diniboy1123/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"fofa-masque/internal/model"
)

const tunnelMTU = 1280
const connectURI = "https://cloudflareaccess.com"

// session owns every socket and forwarding goroutine. The CONNECT request context
// lives until Close, rather than being canceled when the handshake finishes.
type session struct {
	ctx       context.Context
	cancel    context.CancelCauseFunc
	watchDone chan struct{}
	mu        sync.Mutex
	closed    bool
	closers   []func()
	device    tun.Device
	ip        *connectip.Conn
	pumps     sync.WaitGroup
	client    *http.Client
}

func newSession(parent context.Context) *session {
	ctx, cancel := context.WithCancelCause(parent)
	s := &session{ctx: ctx, cancel: cancel, watchDone: make(chan struct{})}
	go func() {
		defer close(s.watchDone)
		<-ctx.Done()
		s.mu.Lock()
		s.closed = true
		closers, device := s.closers, s.device
		s.closers = nil
		s.mu.Unlock()
		// Close the underlying transports before CONNECT-IP: its QUIC stream
		// Close must not race a blocked SendDatagram/Write in a packet pump.
		for _, closeResource := range closers {
			closeResource()
		}
		if device != nil {
			_ = device.Close()
		}
	}()
	return s
}

func (s *session) own(closeResource func()) {
	s.mu.Lock()
	closed := s.closed
	if !closed {
		s.closers = append(s.closers, closeResource)
	}
	s.mu.Unlock()
	if closed {
		closeResource()
	}
}

func (s *session) ownDevice(device tun.Device) {
	s.mu.Lock()
	closed := s.closed
	if !closed {
		s.device = device
	}
	s.mu.Unlock()
	if closed {
		_ = device.Close()
	}
}

func (s *session) Close() {
	s.cancel(context.Canceled)
	<-s.watchDone
	s.pumps.Wait()
	if s.ip != nil {
		_ = s.ip.Close()
	}
}

func (s *session) connect(e model.Endpoint, transport string, c *credentials, sni string, timeout time.Duration) error {
	ip, err := netip.ParseAddr(e.IP)
	if err != nil || ip.Zone() != "" || e.Port < 1 || e.Port > 65535 {
		return errors.New("invalid candidate IP or port")
	}
	tlsConfig, err := outerTLS(c, sni)
	if err != nil {
		return err
	}
	// A timer cancels the lifetime context only on handshake timeout. Stopping
	// it after CONNECT preserves the established stream for subsequent requests.
	timer := time.AfterFunc(timeout, func() { s.cancel(fmt.Errorf("MASQUE connect timeout: %w", context.DeadlineExceeded)) })
	defer timer.Stop()
	address := net.JoinHostPort(ip.String(), strconv.Itoa(e.Port))
	var response *http.Response
	switch transport {
	case "tcp":
		tlsConfig.NextProtos = []string{"h2"}
		h2 := &http2.Transport{
			DisableCompression: true,
			DialTLSContext: func(ctx context.Context, network, _ string, _ *tls.Config) (net.Conn, error) {
				// Deliberately ignore URI authority and all proxy environment variables.
				conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
				if err != nil {
					return nil, err
				}
				s.own(func() { _ = conn.Close() })
				secure := tls.Client(conn, tlsConfig)
				if err := secure.HandshakeContext(ctx); err != nil {
					_ = conn.Close()
					return nil, err
				}
				if secure.ConnectionState().NegotiatedProtocol != "h2" {
					_ = conn.Close()
					return nil, errors.New("MASQUE endpoint did not negotiate HTTP/2")
				}
				return secure, nil
			},
		}
		s.own(h2.CloseIdleConnections)
		client := &http.Client{Transport: h2, CheckRedirect: noRedirect}
		s.ip, response, err = connectip.DialH2(s.ctx, client, uritemplate.MustNew(connectURI), connectHeaders())
	case "udp":
		local := &net.UDPAddr{IP: net.IPv4zero}
		if ip.Is6() {
			local.IP = net.IPv6zero
		}
		udp, listenErr := net.ListenUDP("udp", local)
		if listenErr != nil {
			return listenErr
		}
		s.own(func() { _ = udp.Close() })
		qt := &quic.Transport{Conn: udp, ConnectionIDLength: 20}
		s.own(func() { _ = qt.Close() })
		tlsConfig.NextProtos = []string{http3.NextProtoH3}
		qc, dialErr := qt.Dial(s.ctx, &net.UDPAddr{IP: net.IP(ip.AsSlice()), Port: e.Port}, tlsConfig, &quic.Config{
			EnableDatagrams: true, KeepAlivePeriod: 30 * time.Second, HandshakeIdleTimeout: timeout,
		})
		if dialErr != nil {
			return dialErr
		}
		s.own(func() { _ = qc.CloseWithError(0, "session closed") })
		h3 := &http3.Transport{EnableDatagrams: true, DisableCompression: true, AdditionalSettings: map[uint64]uint64{0x276: 1}}
		s.own(func() { _ = h3.Close() })
		// Unlike upstream ConnectTunnel, we retain UDP and QUIC ownership before
		// Dial reads its CONNECT response, so a stalled response is cancellable.
		s.ip, response, err = connectip.Dial(s.ctx, h3.NewClientConn(qc), uritemplate.MustNew(connectURI), "cf-connect-ip", connectHeaders(), true)
	default:
		return errors.New("transport must be tcp or udp")
	}
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return err
	}
	if s.ip == nil || response == nil {
		return errors.New("MASQUE CONNECT returned no tunnel or response")
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("MASQUE CONNECT HTTP %d (expected 200)", response.StatusCode)
	}
	timer.Stop()
	if s.ctx.Err() != nil {
		return context.Cause(s.ctx)
	}
	dns := []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("1.0.0.1")}
	hasIPv4 := false
	for _, address := range c.addresses {
		hasIPv4 = hasIPv4 || address.Is4()
	}
	if !hasIPv4 {
		dns = []netip.Addr{netip.MustParseAddr("2606:4700:4700::1111"), netip.MustParseAddr("2606:4700:4700::1001")}
	}
	device, network, err := netstack.CreateNetTUN(c.addresses, dns, tunnelMTU)
	if err != nil {
		return err
	}
	s.ownDevice(device)
	if s.ctx.Err() != nil {
		return context.Cause(s.ctx)
	}
	inner := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, networkName, address string) (net.Conn, error) {
			conn, err := network.DialContext(ctx, networkName, address)
			if err == nil {
				s.own(func() { _ = conn.Close() })
			}
			return conn, err
		},
		DisableKeepAlives: true, DisableCompression: true, ForceAttemptHTTP2: false,
	}
	s.own(inner.CloseIdleConnections)
	s.client = &http.Client{Transport: inner, CheckRedirect: noRedirect}
	s.pumps.Add(2)
	go s.sendPackets(device)
	go s.receivePackets(device)
	return nil
}

func connectHeaders() http.Header {
	return http.Header{"User-Agent": []string{""}, "Cf-Connect-Proto": []string{"cf-connect-ip"}, "Pq-Enabled": []string{"false"}}
}

func noRedirect(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }

func (s *session) sendPackets(device tun.Device) {
	defer s.pumps.Done()
	buffer := make([]byte, tunnelMTU+1)
	packets := [][]byte{buffer[1:]}
	sizes := make([]int, 1)
	inbound := make([][]byte, 1)
	for {
		_, err := device.Read(packets, sizes, 0)
		if err != nil {
			s.cancel(fmt.Errorf("reading tunnel device: %w", err))
			return
		}
		// Keep draining until device.Close unblocks this read. netstack's
		// WriteNotify sends synchronously; abandoning the reader too early can
		// deadlock stack shutdown behind an in-flight inbound packet's reply.
		if s.ctx.Err() != nil {
			continue
		}
		icmp, err := s.ip.WritePacketBuffer(buffer, 1, sizes[0])
		if err != nil {
			s.cancel(fmt.Errorf("sending tunnel packet: %w", err))
			continue
		}
		if len(icmp) != 0 {
			// Only this pump writes generated ICMP; the netstack device supports
			// simultaneous inbound injection from the receive pump.
			inbound[0] = icmp
			if _, err := device.Write(inbound, 0); err != nil {
				s.cancel(fmt.Errorf("injecting tunnel ICMP: %w", err))
			}
		}
	}
}

func (s *session) receivePackets(device tun.Device) {
	defer s.pumps.Done()
	packets := make([][]byte, 1)
	for {
		packet, err := s.ip.ReadPacketZeroCopy(true)
		if err != nil {
			s.cancel(fmt.Errorf("receiving tunnel packet: %w", err))
			return
		}
		if s.ctx.Err() != nil {
			return
		}
		packets[0] = packet
		if _, err := device.Write(packets, 0); err != nil {
			s.cancel(fmt.Errorf("writing tunnel device: %w", err))
			return
		}
	}
}
