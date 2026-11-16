package runner

import (
	"context"
	"math"
	"reflect"
	"sync"
	"testing"
	"time"

	"fofa-masque/internal/model"
)

type engineFunc func(context.Context, model.Endpoint, string, model.Settings) model.Attempt

func (f engineFunc) Measure(ctx context.Context, endpoint model.Endpoint, transport string, settings model.Settings) model.Attempt {
	return f(ctx, endpoint, transport, settings)
}

func validSettings() model.Settings {
	return model.Settings{Transport: "tcp", MaxLatencyMS: 100, MinSpeedMbps: 1, DownloadBytes: 1024,
		TimeoutSeconds: 5, Samples: 1, RegionLevel: "country", QuotaMode: "total", TargetCount: 1}
}

func candidate(ip, country string) model.Endpoint {
	return model.Endpoint{IP: ip, Port: 443, Country: country, Region: country + "-region", City: country + "-city"}
}

func passing(settings model.Settings) model.Attempt {
	return model.Attempt{Status: "success", LatencyMS: settings.MaxLatencyMS, SpeedMbps: settings.MinSpeedMbps, DownloadBytes: settings.DownloadBytes}
}

func completed(t *testing.T, runner *Runner) model.State {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		state := runner.Snapshot()
		if state.Status != "running" && state.Status != "stopping" {
			return state
		}
		select {
		case <-deadline.C:
			runner.Stop()
			t.Fatal("scan did not finish")
		case <-ticker.C:
		}
	}
}

func TestQuotaBoundaries(t *testing.T) {
	endpoints := []model.Endpoint{candidate("192.0.2.1", "A"), candidate("192.0.2.2", "A"),
		candidate("192.0.2.3", "A"), candidate("192.0.2.4", "B"), candidate("192.0.2.5", "B"), candidate("192.0.2.6", "B")}
	for _, tc := range []struct {
		name       string
		mode       string
		wantIPs    []string
		wantCounts map[string]int
	}{
		{"total", "total", []string{"192.0.2.1", "192.0.2.2"}, map[string]int{"A": 2, "B": 0}},
		{"per region", "per_region", []string{"192.0.2.1", "192.0.2.2", "192.0.2.4", "192.0.2.5"}, map[string]int{"A": 2, "B": 2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls []string
			runner := New(engineFunc(func(_ context.Context, endpoint model.Endpoint, _ string, settings model.Settings) model.Attempt {
				calls = append(calls, endpoint.IP)
				return passing(settings)
			}))
			settings := validSettings()
			settings.QuotaMode, settings.TargetCount = tc.mode, 2
			if err := runner.Start(endpoints, settings); err != nil {
				t.Fatal(err)
			}
			state := completed(t, runner)
			if state.Status != "completed" || state.StopReason != "target_reached" || state.Tested != len(tc.wantIPs) || state.Qualified != len(tc.wantIPs) || state.Total != 6 {
				t.Fatalf("unexpected quota state: %+v", state)
			}
			if !reflect.DeepEqual(calls, tc.wantIPs) || !reflect.DeepEqual(state.Counts, tc.wantCounts) {
				t.Fatalf("calls=%v counts=%v", calls, state.Counts)
			}
		})
	}
}

func TestBothTransportEitherQualifies(t *testing.T) {
	for _, tc := range []struct {
		name      string
		tcpPass   bool
		udpPass   bool
		wantCalls []string
		qualified int
	}{
		{"tcp short circuits", true, true, []string{"tcp"}, 1},
		{"udp rescues tcp", false, true, []string{"tcp", "udp"}, 1},
		{"neither qualifies", false, false, []string{"tcp", "udp"}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls []string
			runner := New(engineFunc(func(_ context.Context, _ model.Endpoint, transport string, settings model.Settings) model.Attempt {
				calls = append(calls, transport)
				attempt := passing(settings)
				if (transport == "tcp" && !tc.tcpPass) || (transport == "udp" && !tc.udpPass) {
					attempt.LatencyMS++
					attempt.Qualified = true // The engine's judgment must not be trusted.
				}
				return attempt
			}))
			settings := validSettings()
			settings.Transport = "both"
			if err := runner.Start([]model.Endpoint{candidate("192.0.2.1", "A")}, settings); err != nil {
				t.Fatal(err)
			}
			state := completed(t, runner)
			if !reflect.DeepEqual(calls, tc.wantCalls) || state.Qualified != tc.qualified || state.Tested != 1 {
				t.Fatalf("calls=%v state=%+v", calls, state)
			}
			for i, attempt := range state.Results[0].Attempts {
				if attempt.Transport != tc.wantCalls[i] {
					t.Fatalf("wrong attempt transport: %+v", attempt)
				}
			}
		})
	}
}

func TestQualificationRecomputed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*model.Attempt)
	}{
		{"failed status", func(a *model.Attempt) { a.Status = "error" }},
		{"slow latency", func(a *model.Attempt) { a.LatencyMS++ }},
		{"negative latency", func(a *model.Attempt) { a.LatencyMS = -1 }},
		{"nan latency", func(a *model.Attempt) { a.LatencyMS = math.NaN() }},
		{"infinite speed", func(a *model.Attempt) { a.SpeedMbps = math.Inf(1) }},
		{"nan speed", func(a *model.Attempt) { a.SpeedMbps = math.NaN() }},
		{"slow download", func(a *model.Attempt) { a.SpeedMbps = 0 }},
		{"partial download", func(a *model.Attempt) { a.DownloadBytes-- }},
		{"extra download", func(a *model.Attempt) { a.DownloadBytes++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := New(engineFunc(func(_ context.Context, _ model.Endpoint, _ string, settings model.Settings) model.Attempt {
				attempt := passing(settings)
				attempt.Qualified = true
				tc.change(&attempt)
				return attempt
			}))
			if err := runner.Start([]model.Endpoint{candidate("192.0.2.1", "A")}, validSettings()); err != nil {
				t.Fatal(err)
			}
			state := completed(t, runner)
			if state.Qualified != 0 || state.Results[0].Qualified || state.Results[0].Attempts[0].Qualified || state.StopReason != "exhausted" {
				t.Fatalf("invalid measurement qualified: %+v", state)
			}
		})
	}
}

func TestDedupFilteringAndExhaustion(t *testing.T) {
	endpoints := []model.Endpoint{candidate("::ffff:192.0.2.1", "A"), candidate("192.0.2.1", "B"),
		candidate("2001:db8::1", "A"), candidate("2001:0db8:0:0:0:0:0:1", "A"), candidate("192.0.2.2", "B")}
	otherPort := candidate("192.0.2.1", "A")
	otherPort.Port = 8443
	endpoints = append(endpoints, otherPort)
	for _, level := range []string{"country", "region", "city"} {
		t.Run(level, func(t *testing.T) {
			runner := New(engineFunc(func(_ context.Context, _ model.Endpoint, _ string, settings model.Settings) model.Attempt {
				return passing(settings)
			}))
			settings := validSettings()
			settings.TargetCount, settings.RegionLevel, settings.QuotaMode = 10, level, "per_region"
			group := model.RegionKey(endpoints[0], level)
			settings.Regions = []string{group, group}
			if err := runner.Start(endpoints, settings); err != nil {
				t.Fatal(err)
			}
			state := completed(t, runner)
			if state.StopReason != "exhausted" || state.Total != 3 || state.Tested != 3 || state.Qualified != 3 || len(state.Counts) != 1 || state.Counts[group] != 3 {
				t.Fatalf("incorrect filtered unique candidates: %+v", state)
			}
			if state.Results[0].Endpoint.IP != "192.0.2.1" || state.Results[1].Endpoint.IP != "2001:db8::1" {
				t.Fatalf("addresses not normalized: %+v", state.Results)
			}
		})
	}
}

func TestCancellationOverlapRestartAndSnapshots(t *testing.T) {
	entered := make(chan struct{})
	var once sync.Once
	runner := New(engineFunc(func(ctx context.Context, endpoint model.Endpoint, _ string, settings model.Settings) model.Attempt {
		if endpoint.IP == "192.0.2.2" {
			once.Do(func() { close(entered) })
			<-ctx.Done()
		}
		return passing(settings)
	}))
	settings := validSettings()
	settings.TargetCount = 3
	settings.Credentials = model.Credentials{PrivateKey: "secret", EndpointPubKey: "public", IPv4: "10.0.0.1"}
	endpoints := []model.Endpoint{candidate("192.0.2.1", "A"), candidate("192.0.2.2", "A"), candidate("192.0.2.3", "A")}
	if err := runner.Start(endpoints, settings); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runner.Stop)
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("engine was not called")
	}
	if err := runner.Start(endpoints, settings); err == nil {
		t.Fatal("overlapping scan accepted")
	}
	state := runner.Snapshot()
	if state.Tested != 1 || state.Current != "192.0.2.2:443" {
		t.Fatalf("missing live progress: %+v", state)
	}
	state.Counts["A"] = 999
	state.Results[0].Endpoint.IP = "changed"
	state.Results[0].Attempts[0].Status = "changed"
	fresh := runner.Snapshot()
	if fresh.Counts["A"] != 1 || fresh.Results[0].Endpoint.IP != "192.0.2.1" || fresh.Results[0].Attempts[0].Status != "success" {
		t.Fatalf("snapshot exposed mutable storage: %+v", fresh)
	}
	runner.Stop()
	state = completed(t, runner)
	if state.Status != "stopped" || state.StopReason != "user" || state.Tested != 1 || state.Qualified != 1 || len(state.Results) != 1 || state.Current != "" {
		t.Fatalf("canceled endpoint was counted: %+v", state)
	}
	settings.TargetCount = 1
	if err := runner.Start(endpoints[:1], settings); err != nil {
		t.Fatal(err)
	}
	state = completed(t, runner)
	if state.StopReason != "target_reached" || state.Tested != 1 || state.Total != 1 {
		t.Fatalf("restart failed: %+v", state)
	}
	runner.Stop()
	if runner.Snapshot().Status != "completed" {
		t.Fatal("idle Stop changed completed state")
	}
}

func TestValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*model.Settings)
	}{
		{"transport", func(s *model.Settings) { s.Transport = "quic" }},
		{"latency zero", func(s *model.Settings) { s.MaxLatencyMS = 0 }},
		{"latency negative", func(s *model.Settings) { s.MaxLatencyMS = -1 }},
		{"latency nan", func(s *model.Settings) { s.MaxLatencyMS = math.NaN() }},
		{"latency infinite", func(s *model.Settings) { s.MaxLatencyMS = math.Inf(1) }},
		{"speed negative", func(s *model.Settings) { s.MinSpeedMbps = -1 }},
		{"speed nan", func(s *model.Settings) { s.MinSpeedMbps = math.NaN() }},
		{"speed infinite", func(s *model.Settings) { s.MinSpeedMbps = math.Inf(1) }},
		{"download zero", func(s *model.Settings) { s.DownloadBytes = 0 }},
		{"download oversized", func(s *model.Settings) { s.DownloadBytes = 1<<30 + 1 }},
		{"timeout zero", func(s *model.Settings) { s.TimeoutSeconds = 0 }},
		{"timeout oversized", func(s *model.Settings) { s.TimeoutSeconds = 121 }},
		{"samples zero", func(s *model.Settings) { s.Samples = 0 }},
		{"samples oversized", func(s *model.Settings) { s.Samples = 11 }},
		{"target zero", func(s *model.Settings) { s.TargetCount = 0 }},
		{"target oversized", func(s *model.Settings) { s.TargetCount = 1000001 }},
		{"level", func(s *model.Settings) { s.RegionLevel = "continent" }},
		{"quota", func(s *model.Settings) { s.QuotaMode = "each" }},
		{"unavailable region", func(s *model.Settings) { s.Regions = []string{"missing"} }},
		{"empty region", func(s *model.Settings) { s.Regions = []string{""} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := New(engineFunc(func(context.Context, model.Endpoint, string, model.Settings) model.Attempt {
				t.Error("invalid inputs reached engine")
				return model.Attempt{}
			}))
			settings := validSettings()
			tc.change(&settings)
			if err := runner.Start([]model.Endpoint{candidate("192.0.2.1", "A")}, settings); err == nil {
				t.Fatal("invalid settings accepted")
			}
			if runner.Snapshot().Status != "idle" {
				t.Fatal("invalid Start changed state")
			}
		})
	}
	for _, endpoints := range [][]model.Endpoint{
		nil, {candidate("not-an-ip", "A")}, {candidate("fe80::1%eth0", "A")},
		{{IP: "192.0.2.1", Port: 0}}, {{IP: "192.0.2.1", Port: 65536}},
	} {
		runner := New(engineFunc(func(context.Context, model.Endpoint, string, model.Settings) model.Attempt { return model.Attempt{} }))
		if err := runner.Start(endpoints, validSettings()); err == nil {
			t.Fatalf("invalid endpoints accepted: %+v", endpoints)
		}
	}
	if err := New(nil).Start([]model.Endpoint{candidate("192.0.2.1", "A")}, validSettings()); err == nil {
		t.Fatal("nil engine accepted")
	}
}

func TestSettingsInclusiveLimitsAndUnknownGroup(t *testing.T) {
	for _, upper := range []bool{false, true} {
		runner := New(engineFunc(func(_ context.Context, _ model.Endpoint, transport string, settings model.Settings) model.Attempt {
			if transport != "udp" {
				t.Errorf("transport = %s, want udp", transport)
			}
			if settings.Credentials.PrivateKey != "key" {
				t.Error("active engine lost credentials")
			}
			return passing(settings)
		}))
		settings := validSettings()
		settings.Transport, settings.MinSpeedMbps = "udp", 0
		settings.Credentials.PrivateKey = "key"
		settings.DownloadBytes, settings.TimeoutSeconds, settings.Samples, settings.TargetCount = 1, 1, 1, 1
		if upper {
			settings.DownloadBytes, settings.TimeoutSeconds, settings.Samples, settings.TargetCount = 1<<30, 120, 10, 1000000
		}
		if err := runner.Start([]model.Endpoint{candidate("192.0.2.1", "")}, settings); err != nil {
			t.Fatal(err)
		}
		state := completed(t, runner)
		if state.Counts["未知"] != 1 || state.Qualified != 1 {
			t.Fatalf("unknown group lost: %+v", state)
		}
	}
}
