package model

// Endpoint is a deduplicated IP:port candidate; region metadata comes only from import.
type Endpoint struct {
	IP      string `json:"ip"`
	Port    int    `json:"port"`
	Country string `json:"country"`
	Region  string `json:"region"`
	City    string `json:"city"`
}

type Credentials struct {
	PrivateKey     string `json:"private_key"`
	EndpointPubKey string `json:"endpoint_pub_key"`
	IPv4           string `json:"ipv4"`
	IPv6           string `json:"ipv6"`
}

type Settings struct {
	Credentials    Credentials `json:"credentials"`
	SNI            string      `json:"sni"`
	Transport      string      `json:"transport"` // tcp, udp, both; either transport passing qualifies an endpoint.
	MaxLatencyMS   float64     `json:"max_latency_ms"`
	MinSpeedMbps   float64     `json:"min_speed_mbps"`
	DownloadBytes  int64       `json:"download_bytes"`
	TimeoutSeconds int         `json:"timeout_seconds"`
	Samples        int         `json:"samples"`
	RegionLevel    string      `json:"region_level"` // country, region, city
	Regions        []string    `json:"regions"`
	QuotaMode      string      `json:"quota_mode"` // total, per_region
	TargetCount    int         `json:"target_count"`
}

type Attempt struct {
	Transport     string  `json:"transport"`
	Status        string  `json:"status"`
	Error         string  `json:"error,omitempty"`
	LatencyMS     float64 `json:"latency_ms"`
	SpeedMbps     float64 `json:"speed_mbps"`
	DownloadBytes int64   `json:"download_bytes"`
	EgressIP      string  `json:"egress_ip,omitempty"`
	Qualified     bool    `json:"qualified"`
}

type Result struct {
	Endpoint  Endpoint  `json:"endpoint"`
	RegionKey string    `json:"region_key"`
	Attempts  []Attempt `json:"attempts"`
	Qualified bool      `json:"qualified"`
}

type State struct {
	Status     string         `json:"status"` // idle, running, stopping, completed, stopped, error
	StopReason string         `json:"stop_reason"`
	Total      int            `json:"total"`
	Tested     int            `json:"tested"`
	Qualified  int            `json:"qualified"`
	Counts     map[string]int `json:"counts"`
	Current    string         `json:"current"`
	Results    []Result       `json:"results"`
	Error      string         `json:"error,omitempty"`
}

func RegionKey(e Endpoint, level string) string {
	value := e.Country
	if level == "region" {
		value = e.Region
	}
	if level == "city" {
		value = e.City
	}
	if value == "" {
		return "未知"
	}
	return value
}
