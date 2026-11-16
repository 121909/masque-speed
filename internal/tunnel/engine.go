package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"fofa-masque/internal/model"
)

const traceURL = "https://www.cloudflare.com/cdn-cgi/trace"
const downloadURL = "https://speed.cloudflare.com/__down"
const traceLimit = 64 << 10

var errLatencyRejected = errors.New("latency exceeds maximum")

type Engine struct{}

func New() *Engine { return &Engine{} }

func (*Engine) Measure(ctx context.Context, endpoint model.Endpoint, transport string, settings model.Settings) model.Attempt {
	attempt := model.Attempt{Transport: transport, Status: "error"}
	fail := func(err error) model.Attempt {
		if ctx.Err() != nil {
			attempt.Status = "error"
			attempt.Error = "measurement canceled: " + ctx.Err().Error()
		} else {
			attempt.Error = err.Error()
		}
		return attempt
	}
	if ctx.Err() != nil {
		return fail(ctx.Err())
	}
	c, err := parseCredentials(settings.Credentials)
	if err != nil {
		return fail(err)
	}
	if settings.TimeoutSeconds <= 0 || settings.Samples <= 0 || settings.DownloadBytes <= 0 || settings.DownloadBytes == int64(^uint64(0)>>1) {
		return fail(errors.New("timeout_seconds, samples, and download_bytes must be positive and download_bytes must allow an extra-byte check"))
	}
	s := newSession(ctx)
	defer s.Close()
	if err := s.connect(endpoint, transport, c, settings.SNI, time.Duration(settings.TimeoutSeconds)*time.Second); err != nil {
		if s.ctx.Err() != nil {
			err = context.Cause(s.ctx)
		}
		return fail(err)
	}
	if err := measureRequests(s.ctx, s.client, settings, traceURL, downloadURL, &attempt); err != nil {
		if errors.Is(err, errLatencyRejected) {
			attempt.Status = "rejected"
		} else if s.ctx.Err() != nil {
			err = context.Cause(s.ctx)
		}
		return fail(err)
	}
	if s.ctx.Err() != nil {
		return fail(context.Cause(s.ctx))
	}
	attempt.Status = "success"
	return attempt
}

// measureRequests excludes the outer MASQUE handshake. Each trace sample starts
// at the HTTP request and includes DNS, inner TCP/TLS, and server response time.
func measureRequests(ctx context.Context, client *http.Client, settings model.Settings, traceAddress, downloadAddress string, attempt *model.Attempt) error {
	timeout := time.Duration(settings.TimeoutSeconds) * time.Second
	latencies := make([]time.Duration, 0, settings.Samples)
	for range settings.Samples {
		latency, ip, err := traceSample(ctx, client, traceAddress, timeout)
		if err != nil {
			return fmt.Errorf("trace request: %w", err)
		}
		latencies = append(latencies, latency)
		attempt.EgressIP = ip
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	middle := len(latencies) / 2
	median := float64(latencies[middle])
	if len(latencies)%2 == 0 {
		median = (float64(latencies[middle-1]) + median) / 2
	}
	attempt.LatencyMS = median / float64(time.Millisecond)
	if attempt.LatencyMS > settings.MaxLatencyMS {
		return fmt.Errorf("%w: %.3f ms > %.3f ms", errLatencyRejected, attempt.LatencyMS, settings.MaxLatencyMS)
	}
	return download(ctx, client, downloadAddress, timeout, settings.DownloadBytes, attempt)
}

func traceSample(parent context.Context, client *http.Client, address string, timeout time.Duration) (time.Duration, string, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	var firstByte atomic.Int64
	start := time.Now()
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotFirstResponseByte: func() { firstByte.CompareAndSwap(0, int64(time.Since(start))) }})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Accept-Encoding", "identity")
	response, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return 0, "", fmt.Errorf("HTTP %d (expected 200)", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, traceLimit+1))
	if err != nil {
		return 0, "", err
	}
	if len(body) > traceLimit {
		return 0, "", errors.New("trace response exceeds 64 KiB")
	}
	ip, err := parseTrace(string(body))
	if err != nil {
		return 0, "", err
	}
	if ctx.Err() != nil {
		return 0, "", ctx.Err()
	}
	latency := time.Duration(firstByte.Load())
	if latency <= 0 {
		return 0, "", errors.New("trace response did not report first-byte timing")
	}
	return latency, ip, nil
}

func parseTrace(body string) (string, error) {
	var warp, ipText string
	for _, line := range strings.Split(body, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch key {
		case "warp":
			if warp != "" {
				return "", errors.New("trace contains duplicate warp fields")
			}
			warp = value
		case "ip":
			if ipText != "" {
				return "", errors.New("trace contains duplicate ip fields")
			}
			ipText = value
		}
	}
	if warp != "on" && warp != "plus" {
		return "", errors.New("trace did not confirm warp=on or warp=plus")
	}
	ip, err := netip.ParseAddr(ipText)
	if err != nil || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() {
		return "", errors.New("trace did not contain a valid egress IP")
	}
	return ip.String(), nil
}

func download(parent context.Context, client *http.Client, address string, timeout time.Duration, bytes int64, attempt *model.Attempt) error {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address+"?bytes="+strconv.FormatInt(bytes, 10), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept-Encoding", "identity")
	start := time.Now()
	response, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("download HTTP %d (expected 200)", response.StatusCode)
	}
	encoding := strings.TrimSpace(strings.Join(response.Header.Values("Content-Encoding"), ","))
	if response.Uncompressed || (encoding != "" && !strings.EqualFold(encoding, "identity")) {
		return errors.New("download response Content-Encoding is not identity")
	}
	// io.Discard.ReadFrom already reuses a pooled copy buffer.
	n, err := io.Copy(io.Discard, io.LimitReader(response.Body, bytes+1))
	elapsed := time.Since(start)
	attempt.DownloadBytes = n
	if err != nil {
		return fmt.Errorf("download body: %w", err)
	}
	if ctx.Err() != nil {
		return fmt.Errorf("download request: %w", ctx.Err())
	}
	if n != bytes {
		return fmt.Errorf("download size mismatch: received %d bytes, expected exactly %d", n, bytes)
	}
	if elapsed <= 0 {
		return errors.New("download elapsed time is not positive")
	}
	attempt.SpeedMbps = float64(n) * 8 / elapsed.Seconds() / 1e6
	return nil
}
