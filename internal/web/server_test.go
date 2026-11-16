package web

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"fofa-masque/internal/model"
	"fofa-masque/internal/runner"
)

const testSessionToken = "web-test-session-secret"

type webTestEngine struct {
	calls atomic.Int32
}

func (e *webTestEngine) Measure(_ context.Context, _ model.Endpoint, _ string, settings model.Settings) model.Attempt {
	e.calls.Add(1)
	return model.Attempt{Status: "success", LatencyMS: 10, SpeedMbps: 8,
		DownloadBytes: settings.DownloadBytes, EgressIP: "198.51.100.90"}
}

func testCredentials(t *testing.T) model.Credentials {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalECPrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&server.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return model.Credentials{
		PrivateKey:     base64.StdEncoding.EncodeToString(privateDER),
		EndpointPubKey: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})),
		IPv4:           "172.16.0.2",
	}
}

func testSettings(credentials model.Credentials) model.Settings {
	return model.Settings{Credentials: credentials, SNI: "example.com", Transport: "tcp",
		MaxLatencyMS: 100, MinSpeedMbps: 1, DownloadBytes: 1024, TimeoutSeconds: 5,
		Samples: 1, RegionLevel: "country", QuotaMode: "total", TargetCount: 1}
}

func jsonBody(t *testing.T, value any) string {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func apiRequest(handler http.Handler, method, path, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "http://127.0.0.1:32123"+path, strings.NewReader(body))
	request.Header.Set("X-Session-Token", testSessionToken)
	request.Header.Set("Origin", "http://127.0.0.1:32123")
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func requireStatus(t *testing.T, response *httptest.ResponseRecorder, want int) {
	t.Helper()
	if response.Code != want {
		t.Fatalf("HTTP status = %d, want %d; body: %s", response.Code, want, response.Body.String())
	}
}

func waitForAPIScan(t *testing.T, handler http.Handler) model.State {
	t.Helper()
	timeout := time.NewTimer(3 * time.Second)
	defer timeout.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		response := apiRequest(handler, http.MethodGet, "/api/state", "")
		requireStatus(t, response, http.StatusOK)
		var state model.State
		if err := json.Unmarshal(response.Body.Bytes(), &state); err != nil {
			t.Fatal(err)
		}
		if state.Status != "running" && state.Status != "stopping" {
			return state
		}
		select {
		case <-timeout.C:
			t.Fatal("API scan did not finish")
		case <-ticker.C:
		}
	}
}

func TestAPIAuthenticationAndLoopbackGuards(t *testing.T) {
	handler := New(runner.New(&webTestEngine{}), testSessionToken, filepath.Join(t.TempDir(), "credentials.json"))
	for _, path := range []string{"/api/state", "/api/credentials"} {
		for _, token := range []string{"", "wrong-token"} {
			t.Run(path+"/"+token, func(t *testing.T) {
				request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:32123"+path, nil)
				request.Header.Set("X-Session-Token", token)
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				requireStatus(t, response, http.StatusUnauthorized)
			})
		}
	}
	for _, tc := range []struct {
		name, host, origin, site string
	}{
		{"evil host", "evil.example:32123", "http://evil.example:32123", "same-origin"},
		{"host suffix", "localhost.evil.example:32123", "", ""},
		{"cross origin", "127.0.0.1:32123", "https://evil.example", "same-origin"},
		{"other loopback origin", "127.0.0.1:32123", "http://localhost:32123", "same-origin"},
		{"cross site", "127.0.0.1:32123", "http://127.0.0.1:32123", "cross-site"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "http://"+tc.host+"/api/state", nil)
			request.Header.Set("X-Session-Token", testSessionToken)
			request.Header.Set("Origin", tc.origin)
			request.Header.Set("Sec-Fetch-Site", tc.site)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			requireStatus(t, response, http.StatusForbidden)
		})
	}
	for _, host := range []string{"127.0.0.1:32123", "localhost:32123", "[::1]:32123"} {
		t.Run(host, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "http://"+host+"/api/state", nil)
			request.Header.Set("X-Session-Token", testSessionToken)
			request.Header.Set("Origin", "http://"+host)
			request.Header.Set("Sec-Fetch-Site", "same-origin")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			requireStatus(t, response, http.StatusOK)
			var state model.State
			if err := json.Unmarshal(response.Body.Bytes(), &state); err != nil || state.Status != "idle" {
				t.Fatalf("authenticated state = %+v, error = %v", state, err)
			}
		})
	}
}

func TestCredentialsExplicitSaveAndDelete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "credentials.json")
	handler := New(runner.New(&webTestEngine{}), testSessionToken, path)
	credentials := testCredentials(t)
	requireStatus(t, apiRequest(handler, http.MethodGet, "/api/credentials", ""), http.StatusNotFound)
	requireStatus(t, apiRequest(handler, http.MethodGet, "/api/state", ""), http.StatusOK)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("read-only requests created credentials: %v", err)
	}

	invalid := credentials
	invalid.PrivateKey = "not-an-ecdsa-key"
	requireStatus(t, apiRequest(handler, http.MethodPost, "/api/credentials", jsonBody(t, invalid)), http.StatusBadRequest)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("invalid credentials were saved: %v", err)
	}
	requireStatus(t, apiRequest(handler, http.MethodPost, "/api/credentials", jsonBody(t, credentials)), http.StatusOK)
	response := apiRequest(handler, http.MethodGet, "/api/credentials", "")
	requireStatus(t, response, http.StatusOK)
	var loaded model.Credentials
	if err := json.Unmarshal(response.Body.Bytes(), &loaded); err != nil {
		t.Fatal(err)
	}
	if loaded != credentials {
		t.Fatal("saved credentials did not round trip unchanged")
	}
	if runtime.GOOS != "windows" {
		for _, tc := range []struct {
			path string
			mode os.FileMode
		}{{path, 0600}, {filepath.Dir(path), 0700}} {
			info, err := os.Stat(tc.path)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != tc.mode {
				t.Fatalf("permissions of %s = %04o, want %04o", tc.path, info.Mode().Perm(), tc.mode)
			}
		}
	}

	// Rejected replacements must preserve the explicitly saved credentials.
	requireStatus(t, apiRequest(handler, http.MethodPost, "/api/credentials", jsonBody(t, invalid)), http.StatusBadRequest)
	response = apiRequest(handler, http.MethodGet, "/api/credentials", "")
	requireStatus(t, response, http.StatusOK)
	if err := json.Unmarshal(response.Body.Bytes(), &loaded); err != nil || loaded != credentials {
		t.Fatalf("invalid replacement changed saved credentials: %v", err)
	}
	requireStatus(t, apiRequest(handler, http.MethodDelete, "/api/credentials", ""), http.StatusOK)
	requireStatus(t, apiRequest(handler, http.MethodGet, "/api/credentials", ""), http.StatusNotFound)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("deleted credentials still exist: %v", err)
	}
}

func TestAPIImportStartAndSafeQualifiedExport(t *testing.T) {
	credentials := testCredentials(t)
	for _, tc := range []struct {
		name, country, region, city string
	}{
		{"arithmetic prefixes", "=1+1", "+SUM(1,2)", "-1+2"},
		{"at prefix and controls", "@SUM(1,2)", "a\tb", "line\nbreak"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engine := &webTestEngine{}
			scan := runner.New(engine)
			t.Cleanup(scan.Stop)
			path := filepath.Join(t.TempDir(), "private", "credentials.json")
			handler := New(scan, testSessionToken, path)
			input := []model.Endpoint{
				{IP: "192.0.2.1", Port: 443, Country: tc.country, Region: tc.region, City: tc.city},
				{IP: "192.0.2.2", Port: 8443, Country: "not-exported"},
			}
			response := apiRequest(handler, http.MethodPost, "/api/import?filename=assets.json", jsonBody(t, input))
			requireStatus(t, response, http.StatusOK)
			var imported struct {
				Endpoints []model.Endpoint          `json:"endpoints"`
				Warnings  []string                  `json:"warnings"`
				Regions   map[string]map[string]int `json:"regions"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &imported); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(imported.Endpoints, input) || len(imported.Warnings) != 0 {
				t.Fatalf("import changed metadata: %+v", imported)
			}
			request := map[string]any{"endpoints": imported.Endpoints, "settings": testSettings(credentials)}
			response = apiRequest(handler, http.MethodPost, "/api/start", jsonBody(t, request))
			requireStatus(t, response, http.StatusOK)
			state := waitForAPIScan(t, handler)
			if state.Status != "completed" || state.StopReason != "target_reached" || state.Qualified != 1 || state.Tested != 1 || engine.calls.Load() != 1 {
				t.Fatalf("unexpected API scan result: %+v; engine calls = %d", state, engine.calls.Load())
			}

			for _, endpoint := range []string{"/api/state", "/api/export"} {
				response = apiRequest(handler, http.MethodGet, endpoint, "")
				requireStatus(t, response, http.StatusOK)
				for _, secret := range []string{"private_key", "access_token", credentials.PrivateKey, testSessionToken} {
					if strings.Contains(response.Body.String(), secret) {
						t.Fatalf("%s exposed %q", endpoint, secret)
					}
				}
			}
			rows, err := csv.NewReader(strings.NewReader(response.Body.String())).ReadAll()
			if err != nil {
				t.Fatal(err)
			}
			want := [][]string{
				{"ip", "port", "country", "region", "city", "transport", "latency_ms", "speed_mbps", "egress_ip"},
				{"192.0.2.1", "443", "'" + tc.country, "'" + tc.region, "'" + tc.city, "tcp", "10", "8", "198.51.100.90"},
			}
			if !reflect.DeepEqual(rows, want) {
				t.Fatalf("CSV = %#v, want exactly one sanitized qualified row %#v", rows, want)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("scan implicitly persisted credentials: %v", err)
			}
			requireStatus(t, apiRequest(handler, http.MethodGet, "/api/credentials", ""), http.StatusNotFound)
		})
	}
}

func TestInvalidCredentialsDoNotModifyScan(t *testing.T) {
	engine := &webTestEngine{}
	scan := runner.New(engine)
	t.Cleanup(scan.Stop)
	handler := New(scan, testSessionToken, filepath.Join(t.TempDir(), "credentials.json"))
	credentials := testCredentials(t)
	endpoints := []model.Endpoint{{IP: "192.0.2.1", Port: 443, Country: "original"}}
	request := map[string]any{"endpoints": endpoints, "settings": testSettings(credentials)}
	requireStatus(t, apiRequest(handler, http.MethodPost, "/api/start", jsonBody(t, request)), http.StatusOK)
	before := waitForAPIScan(t, handler)
	if before.Status != "completed" {
		t.Fatalf("baseline scan did not complete: %+v", before)
	}
	calls := engine.calls.Load()
	for _, tc := range []struct {
		name   string
		change func(*model.Credentials)
	}{
		{"private key", func(c *model.Credentials) { c.PrivateKey = "invalid-private-key" }},
		{"server public key", func(c *model.Credentials) { c.EndpointPubKey = "invalid-public-key" }},
		{"assigned IPv4", func(c *model.Credentials) { c.IPv4 = "not-an-address" }},
		{"missing addresses", func(c *model.Credentials) { c.IPv4 = ""; c.IPv6 = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			invalid := credentials
			tc.change(&invalid)
			body := map[string]any{
				"endpoints": []model.Endpoint{{IP: "192.0.2.99", Port: 8443, Country: "replacement"}},
				"settings":  testSettings(invalid),
			}
			requireStatus(t, apiRequest(handler, http.MethodPost, "/api/start", jsonBody(t, body)), http.StatusBadRequest)
			if after := scan.Snapshot(); !reflect.DeepEqual(after, before) || engine.calls.Load() != calls {
				t.Fatalf("invalid credentials modified scan: before=%+v after=%+v calls=%d", before, after, engine.calls.Load())
			}
		})
	}
}

func TestAPIRejectsMalformedImportFields(t *testing.T) {
	handler := New(runner.New(&webTestEngine{}), testSessionToken, filepath.Join(t.TempDir(), "credentials.json"))
	for _, body := range []string{
		`{"fields":7,"results":[["192.0.2.1",443]]}`,
		`{"fields":"ip,port","results":[["192.0.2.1",443]]}`,
		`{"fields":["ip",false],"results":[["192.0.2.1",443]]}`,
		`{"fields":["ip","port","PORT"],"results":[["192.0.2.1",443,443]]}`,
		`{"fields":["ip","port"],"results":{}}`,
	} {
		response := apiRequest(handler, http.MethodPost, "/api/import?filename=bad.json", body)
		requireStatus(t, response, http.StatusBadRequest)
		var failure struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &failure); err != nil || failure.Error == "" {
			t.Fatalf("malformed import lacks a JSON error response: %s, %v", response.Body.String(), err)
		}
	}
}

func TestAPIStrictJSONRequests(t *testing.T) {
	credentials := testCredentials(t)
	settings := testSettings(credentials)
	start := jsonBody(t, map[string]any{
		"endpoints": []model.Endpoint{{IP: "192.0.2.1", Port: 443}}, "settings": settings,
	})
	credentialBody := jsonBody(t, credentials)
	for _, tc := range []struct{ name, path, body string }{
		{"credentials unknown", "/api/credentials", strings.TrimSuffix(credentialBody, "}") + `,"unexpected":true}`},
		{"credentials trailing object", "/api/credentials", credentialBody + `{}`},
		{"credentials trailing null", "/api/credentials", credentialBody + ` null`},
		{"start unknown", "/api/start", strings.TrimSuffix(start, "}") + `,"unexpected":true}`},
		{"start nested unknown", "/api/start", strings.Replace(start, `"settings":{`, `"settings":{"unexpected":true,`, 1)},
		{"start trailing object", "/api/start", start + `{}`},
		{"start trailing garbage", "/api/start", start + ` garbage`},
		{"stop unknown", "/api/stop", `{"unexpected":true}`},
		{"stop trailing object", "/api/stop", `{} {}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engine := &webTestEngine{}
			scan := runner.New(engine)
			path := filepath.Join(t.TempDir(), "private", "credentials.json")
			handler := New(scan, testSessionToken, path)
			requireStatus(t, apiRequest(handler, http.MethodPost, tc.path, tc.body), http.StatusBadRequest)
			if state := scan.Snapshot(); state.Status != "idle" || engine.calls.Load() != 0 {
				t.Fatalf("rejected JSON changed scan: %+v", state)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("rejected JSON saved credentials: %v", err)
			}
		})
	}
}
