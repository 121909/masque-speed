package runner

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"fofa-masque/internal/model"
)

// Engine measures a single endpoint using the requested outer transport.
// Successful measurements use status "success"; Runner determines qualification.
type Engine interface {
	Measure(context.Context, model.Endpoint, string, model.Settings) model.Attempt
}

type Runner struct {
	mu     sync.Mutex
	engine Engine
	cancel context.CancelFunc
	state  model.State
}

func New(engine Engine) *Runner {
	return &Runner{engine: engine, state: model.State{Status: "idle", Counts: make(map[string]int)}}
}

// Start validates and copies its inputs before starting one asynchronous scan.
func (r *Runner) Start(endpoints []model.Endpoint, settings model.Settings) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cancel != nil {
		return errors.New("a scan is already running")
	}
	if r.engine == nil {
		return errors.New("measurement engine is required")
	}
	candidates, groups, err := prepare(endpoints, &settings)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.state = model.State{Status: "running", Total: len(candidates), Counts: make(map[string]int, len(groups))}
	for group := range groups {
		r.state.Counts[group] = 0
	}
	go r.run(ctx, candidates, settings)
	return nil
}

func (r *Runner) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cancel != nil {
		r.state.Status = "stopping"
		r.cancel()
	}
}

// Snapshot never exposes scan settings or mutable storage owned by the runner.
func (r *Runner) Snapshot() model.State {
	r.mu.Lock()
	defer r.mu.Unlock()
	state := r.state
	state.Counts = make(map[string]int, len(r.state.Counts))
	for key, count := range r.state.Counts {
		state.Counts[key] = count
	}
	state.Results = make([]model.Result, len(r.state.Results))
	for i, result := range r.state.Results {
		state.Results[i] = result
		state.Results[i].Attempts = append([]model.Attempt(nil), result.Attempts...)
	}
	return state
}

func (r *Runner) run(ctx context.Context, endpoints []model.Endpoint, settings model.Settings) {
	defer func() { settings = model.Settings{} }()
	transports := []string{settings.Transport}
	if settings.Transport == "both" {
		transports = []string{"tcp", "udp"}
	}
	for _, endpoint := range endpoints {
		group := model.RegionKey(endpoint, settings.RegionLevel)
		r.mu.Lock()
		if ctx.Err() != nil {
			r.finishLocked("stopped", "user")
			r.mu.Unlock()
			return
		}
		if settings.QuotaMode == "per_region" && r.state.Counts[group] >= settings.TargetCount {
			r.mu.Unlock()
			continue
		}
		r.state.Current = net.JoinHostPort(endpoint.IP, strconv.Itoa(endpoint.Port))
		r.mu.Unlock()

		result := model.Result{Endpoint: endpoint, RegionKey: group}
		for _, transport := range transports {
			if ctx.Err() != nil {
				break
			}
			attempt := r.engine.Measure(ctx, endpoint, transport, settings)
			attempt.Transport = transport
			attempt.Qualified = attempt.Status == "success" && finite(attempt.LatencyMS) && attempt.LatencyMS >= 0 &&
				attempt.LatencyMS <= settings.MaxLatencyMS && finite(attempt.SpeedMbps) &&
				attempt.SpeedMbps >= settings.MinSpeedMbps && attempt.DownloadBytes == settings.DownloadBytes
			result.Attempts = append(result.Attempts, attempt)
			if attempt.Qualified {
				result.Qualified = true
				break
			}
		}

		r.mu.Lock()
		if ctx.Err() != nil {
			r.finishLocked("stopped", "user")
			r.mu.Unlock()
			return
		}
		r.state.Tested++
		r.state.Results = append(r.state.Results, result)
		r.state.Current = ""
		if result.Qualified {
			r.state.Qualified++
			r.state.Counts[group]++
		}
		reached := r.state.Qualified >= settings.TargetCount
		if settings.QuotaMode == "per_region" {
			reached = true
			for _, count := range r.state.Counts {
				if count < settings.TargetCount {
					reached = false
					break
				}
			}
		}
		if reached {
			r.finishLocked("completed", "target_reached")
			r.mu.Unlock()
			return
		}
		r.mu.Unlock()
	}
	r.mu.Lock()
	if ctx.Err() != nil {
		r.finishLocked("stopped", "user")
	} else {
		r.finishLocked("completed", "exhausted")
	}
	r.mu.Unlock()
}

func (r *Runner) finishLocked(status, reason string) {
	r.state.Status = status
	r.state.StopReason = reason
	r.state.Current = ""
	r.cancel()
	r.cancel = nil
}

func finite(value float64) bool { return !math.IsNaN(value) && !math.IsInf(value, 0) }

func prepare(endpoints []model.Endpoint, settings *model.Settings) ([]model.Endpoint, map[string]struct{}, error) {
	if settings.Transport != "tcp" && settings.Transport != "udp" && settings.Transport != "both" {
		return nil, nil, errors.New("transport must be tcp, udp, or both")
	}
	if !finite(settings.MaxLatencyMS) || settings.MaxLatencyMS <= 0 || !finite(settings.MinSpeedMbps) || settings.MinSpeedMbps < 0 {
		return nil, nil, errors.New("latency must be positive and speed nonnegative, both finite")
	}
	if settings.DownloadBytes < 1 || settings.DownloadBytes > 1<<30 || settings.TimeoutSeconds < 1 || settings.TimeoutSeconds > 120 ||
		settings.Samples < 1 || settings.Samples > 10 || settings.TargetCount < 1 || settings.TargetCount > 1000000 {
		return nil, nil, errors.New("download bytes, timeout, samples, or target count is outside its supported range")
	}
	if settings.RegionLevel != "country" && settings.RegionLevel != "region" && settings.RegionLevel != "city" {
		return nil, nil, errors.New("region level must be country, region, or city")
	}
	if settings.QuotaMode != "total" && settings.QuotaMode != "per_region" {
		return nil, nil, errors.New("quota mode must be total or per_region")
	}
	if len(endpoints) == 0 {
		return nil, nil, errors.New("at least one endpoint is required")
	}
	unique := make(map[netip.AddrPort]struct{}, len(endpoints))
	available := make(map[string]struct{})
	candidates := make([]model.Endpoint, 0, len(endpoints))
	for i, endpoint := range endpoints {
		ip, err := netip.ParseAddr(strings.TrimSpace(endpoint.IP))
		if err != nil || ip.Zone() != "" || endpoint.Port < 1 || endpoint.Port > 65535 {
			return nil, nil, fmt.Errorf("endpoint %d must have a valid IP and port 1..65535", i+1)
		}
		ip = ip.Unmap()
		key := netip.AddrPortFrom(ip, uint16(endpoint.Port))
		if _, exists := unique[key]; exists {
			continue
		}
		unique[key] = struct{}{}
		endpoint.IP = ip.String()
		endpoint.Country = strings.TrimSpace(endpoint.Country)
		endpoint.Region = strings.TrimSpace(endpoint.Region)
		endpoint.City = strings.TrimSpace(endpoint.City)
		available[model.RegionKey(endpoint, settings.RegionLevel)] = struct{}{}
		candidates = append(candidates, endpoint)
	}
	selected := make(map[string]struct{}, len(settings.Regions))
	for _, region := range settings.Regions {
		region = strings.TrimSpace(region)
		if _, exists := available[region]; !exists {
			return nil, nil, fmt.Errorf("selected region %q has no endpoints", region)
		}
		selected[region] = struct{}{}
	}
	if len(selected) == 0 {
		selected = available
	}
	filtered := candidates[:0]
	for _, endpoint := range candidates {
		if _, exists := selected[model.RegionKey(endpoint, settings.RegionLevel)]; exists {
			filtered = append(filtered, endpoint)
		}
	}
	// The worker does not need the caller-owned region slice after filtering.
	settings.Regions = nil
	return filtered, selected, nil
}
