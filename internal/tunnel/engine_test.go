package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"fofa-masque/internal/model"
)

func TestParseTrace(t *testing.T) {
	for _, body := range []string{"warp=on\nip=203.0.113.7\n", "ip=2001:db8::7\nwarp=plus\n"} {
		if _, err := parseTrace(body); err != nil {
			t.Fatal(err)
		}
	}
	for _, body := range []string{"warp=off\nip=203.0.113.7", "warp=on\nip=not-an-ip", "warp=on", "ip=203.0.113.7", "warp=on\nip=0.0.0.0", "warp=on\nwarp=off\nip=203.0.113.7", "warp=on\nip=203.0.113.7\nip=203.0.113.8"} {
		if _, err := parseTrace(body); err == nil {
			t.Fatalf("invalid trace accepted: %q", body)
		}
	}
}

func requestSettings() model.Settings {
	return model.Settings{TimeoutSeconds: 2, Samples: 3, DownloadBytes: 1024, MaxLatencyMS: 10000, MinSpeedMbps: 1e12}
}

func TestMeasureRequestsRequiresAllSamplesAndExactDownload(t *testing.T) {
	var traces, downloads atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/trace":
			traces.Add(1)
			fmt.Fprint(w, "warp=plus\nip=203.0.113.5\n")
		case "/download":
			downloads.Add(1)
			if r.Header.Get("Accept-Encoding") != "identity" || r.URL.Query().Get("bytes") != "1024" {
				t.Error("download did not request exact identity bytes")
			}
			fmt.Fprint(w, strings.Repeat("x", 1024))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	attempt := model.Attempt{}
	if err := measureRequests(context.Background(), server.Client(), requestSettings(), server.URL+"/trace", server.URL+"/download", &attempt); err != nil {
		t.Fatal(err)
	}
	if traces.Load() != 3 || downloads.Load() != 1 {
		t.Fatalf("trace/download counts = %d/%d", traces.Load(), downloads.Load())
	}
	if attempt.LatencyMS <= 0 || attempt.SpeedMbps <= 0 || attempt.DownloadBytes != 1024 || attempt.EgressIP != "203.0.113.5" {
		t.Fatalf("invalid metrics: %+v", attempt)
	}
}

func TestMeasureRequestsDoesNotDownloadOnTraceOrLatencyFailure(t *testing.T) {
	for _, tc := range []struct {
		name, trace string
		max         float64
		rejected    bool
	}{
		{"warp off", "warp=off\nip=203.0.113.1\n", 10000, false},
		{"latency limit", "warp=on\nip=203.0.113.1\n", 0, true},
		{"oversized trace", strings.Repeat("x", traceLimit+1), 10000, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var downloads atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/trace" {
					fmt.Fprint(w, tc.trace)
				} else {
					downloads.Add(1)
				}
			}))
			defer server.Close()
			s := requestSettings()
			s.MaxLatencyMS = tc.max
			err := measureRequests(context.Background(), server.Client(), s, server.URL+"/trace", server.URL+"/download", &model.Attempt{})
			if err == nil || errors.Is(err, errLatencyRejected) != tc.rejected {
				t.Fatalf("unexpected error: %v", err)
			}
			if downloads.Load() != 0 {
				t.Fatal("download started after failed trace/latency")
			}
		})
	}
}

func TestDownloadRejectsInvalidResponses(t *testing.T) {
	for _, tc := range []struct {
		name           string
		status         int
		encoding, body string
	}{
		{"short", 200, "", "xxx"},
		{"long", 200, "", "xxxxx"},
		{"encoded", 200, "gzip", "xxxx"},
		{"status", 503, "", "xxxx"},
		{"redirect", 302, "", "xxxx"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.encoding != "" {
					w.Header().Set("Content-Encoding", tc.encoding)
				}
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			}))
			defer server.Close()
			client := server.Client()
			client.CheckRedirect = noRedirect
			if err := download(context.Background(), client, server.URL, time.Second, 4, &model.Attempt{}); err == nil {
				t.Fatal("invalid download accepted")
			}
		})
	}
}

func TestTraceRequestCancellation(t *testing.T) {
	started := make(chan struct{})
	finished := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		close(finished)
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, _, err := traceSample(ctx, server.Client(), server.URL, time.Second); done <- err }()
	<-started
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled request succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("request cancellation blocked")
	}
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("server request not canceled")
	}
}
