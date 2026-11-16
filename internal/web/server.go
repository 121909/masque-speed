package web

import (
	"crypto/subtle"
	"embed"
	"encoding/csv"
	"encoding/json"
	"io"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"unicode"

	"fofa-masque/internal/importer"
	"fofa-masque/internal/model"
	"fofa-masque/internal/runner"
	"fofa-masque/internal/tunnel"
)

//go:embed static/*
var assets embed.FS

const maxBody = 32 << 20

// Normalized endpoint JSON can be substantially larger than the raw import.
const maxStartBody = 512 << 20

// New exposes a loopback UI and a session-authenticated API. Tokens are never embedded in assets.
func New(scan *runner.Runner, token string, credentialsPath string) http.Handler {
	static, err := fs.Sub(assets, "static")
	if err != nil {
		panic("embedded assets unavailable")
	}
	files := http.FileServer(http.FS(static))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		w.Header().Set("Cache-Control", "no-store")
		host, _, hostErr := net.SplitHostPort(r.Host)
		if hostErr != nil || (host != "127.0.0.1" && host != "localhost" && host != "::1") {
			fail(w, 403, "host rejected")
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				fail(w, 405, "method not allowed")
				return
			}
			files.ServeHTTP(w, r)
			return
		}
		if token == "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Session-Token")), []byte(token)) != 1 {
			fail(w, 401, "unauthorized")
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" && origin != "http://"+r.Host {
			fail(w, 403, "origin rejected")
			return
		}
		if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
			fail(w, 403, "cross-site request rejected")
			return
		}
		switch r.URL.Path {
		case "/api/import":
			if !method(w, r, http.MethodPost) {
				return
			}
			if status := scan.Snapshot().Status; status == "running" || status == "stopping" {
				fail(w, 409, "scan already active")
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, maxBody)
			data, err := io.ReadAll(r.Body)
			if err != nil {
				fail(w, 413, "import exceeds size limit or could not be read")
				return
			}
			endpoints, warnings, err := importer.Parse(data, r.URL.Query().Get("filename"))
			if err != nil {
				fail(w, 400, err.Error())
				return
			}
			regions := make(map[string]map[string]int, 3)
			for _, level := range []string{"country", "region", "city"} {
				counts := make(map[string]int)
				for _, endpoint := range endpoints {
					counts[model.RegionKey(endpoint, level)]++
				}
				regions[level] = counts
			}
			respond(w, map[string]any{"endpoints": endpoints, "warnings": warnings, "regions": regions})
		case "/api/start":
			if !method(w, r, http.MethodPost) {
				return
			}
			var request struct {
				Endpoints []model.Endpoint `json:"endpoints"`
				Settings  model.Settings   `json:"settings"`
			}
			if !decode(w, r, &request, maxStartBody) {
				return
			}
			if err := tunnel.ValidateCredentials(request.Settings.Credentials); err != nil {
				fail(w, 400, err.Error())
				return
			}
			sni := request.Settings.SNI
			if sni == "" || len(sni) > 253 || strings.IndexFunc(sni, unicode.IsSpace) >= 0 {
				fail(w, 400, "invalid SNI")
				return
			}
			if err := scan.Start(request.Endpoints, request.Settings); err != nil {
				status := scan.Snapshot().Status
				if status == "running" || status == "stopping" || strings.Contains(strings.ToLower(err.Error()), "already running") {
					fail(w, 409, err.Error())
				} else {
					fail(w, 400, err.Error())
				}
				return
			}
			respond(w, scan.Snapshot())
		case "/api/state":
			if method(w, r, http.MethodGet) {
				respond(w, scan.Snapshot())
			}
		case "/api/stop":
			if !method(w, r, http.MethodPost) {
				return
			}
			var body struct{}
			if !decode(w, r, &body, 1024) {
				return
			}
			scan.Stop()
			respond(w, scan.Snapshot())
		case "/api/credentials":
			switch r.Method {
			case http.MethodGet:
				credentials, err := loadCredentials(credentialsPath)
				if os.IsNotExist(err) {
					fail(w, 404, "credentials not saved")
					return
				}
				if err != nil {
					fail(w, 500, "could not read credentials")
					return
				}
				respond(w, credentials)
			case http.MethodPost:
				var credentials model.Credentials
				if !decode(w, r, &credentials, 65536) {
					return
				}
				if err := tunnel.ValidateCredentials(credentials); err != nil {
					fail(w, 400, err.Error())
					return
				}
				if err := saveCredentials(credentialsPath, credentials); err != nil {
					fail(w, 500, "could not save credentials")
					return
				}
				respond(w, map[string]bool{"saved": true})
			case http.MethodDelete:
				if err := os.Remove(credentialsPath); err != nil && !os.IsNotExist(err) {
					fail(w, 500, "could not delete credentials")
					return
				}
				respond(w, map[string]bool{"saved": false})
			default:
				w.Header().Set("Allow", "GET, POST, DELETE")
				fail(w, 405, "method not allowed")
			}
		case "/api/export":
			if !method(w, r, http.MethodGet) {
				return
			}
			snapshot := scan.Snapshot()
			w.Header().Set("Content-Type", "text/csv; charset=utf-8")
			w.Header().Set("Content-Disposition", `attachment; filename="qualified.csv"`)
			writer := csv.NewWriter(w)
			if writer.Write([]string{"ip", "port", "country", "region", "city", "transport", "latency_ms", "speed_mbps", "egress_ip"}) != nil {
				return
			}
			for _, result := range snapshot.Results {
				if !result.Qualified {
					continue
				}
				for _, attempt := range result.Attempts {
					if !attempt.Qualified {
						continue
					}
					endpoint := result.Endpoint
					row := []string{csvText(endpoint.IP), strconv.Itoa(endpoint.Port), csvText(endpoint.Country), csvText(endpoint.Region), csvText(endpoint.City), csvText(attempt.Transport), strconv.FormatFloat(attempt.LatencyMS, 'f', -1, 64), strconv.FormatFloat(attempt.SpeedMbps, 'f', -1, 64), csvText(attempt.EgressIP)}
					if writer.Write(row) != nil {
						return
					}
				}
			}
			writer.Flush()
		default:
			fail(w, 404, "not found")
		}
	})
}

func method(w http.ResponseWriter, r *http.Request, expected string) bool {
	if r.Method == expected {
		return true
	}
	w.Header().Set("Allow", expected)
	fail(w, 405, "method not allowed")
	return false
}

func decode(w http.ResponseWriter, r *http.Request, target any, limit int64) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		fail(w, 415, "application/json required")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		fail(w, 400, "invalid JSON body")
		return false
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		fail(w, 400, "only one JSON value is permitted")
		return false
	}
	return true
}

func respond(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(value)
}

func fail(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func csvText(value string) string {
	trimmed := strings.TrimLeftFunc(value, unicode.IsSpace)
	if trimmed != "" && strings.ContainsRune("=+-@", rune(trimmed[0])) {
		return "'" + value
	}
	if strings.ContainsAny(value, "\t\r\n") {
		return "'" + value
	}
	return value
}
