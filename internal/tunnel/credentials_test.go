package tunnel

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"

	"fofa-masque/internal/model"
)

func testCredentials(t *testing.T) model.Credentials {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return model.Credentials{PrivateKey: base64.StdEncoding.EncodeToString(private), EndpointPubKey: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public})), IPv4: "172.16.0.2", IPv6: "2606:4700:110::2"}
}

func TestCredentialEncodings(t *testing.T) {
	c := testCredentials(t)
	parsed, err := parseCredentials(c)
	if err != nil {
		t.Fatal(err)
	}
	sec1, _ := x509.MarshalECPrivateKey(parsed.private)
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(parsed.private)
	public, _ := x509.MarshalPKIXPublicKey(parsed.public)
	for _, private := range []string{
		c.PrivateKey,
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})),
	} {
		for _, pub := range []string{c.EndpointPubKey, base64.StdEncoding.EncodeToString(public)} {
			candidate := c
			candidate.PrivateKey, candidate.EndpointPubKey = private, pub
			candidate.IPv4 = "" // IPv6-only credentials are valid.
			if err := ValidateCredentials(candidate); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestCredentialRejectionsAreKeySafe(t *testing.T) {
	base := testCredentials(t)
	other, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	private, _ := x509.MarshalECPrivateKey(other)
	public, _ := x509.MarshalPKIXPublicKey(&other.PublicKey)
	cases := []struct {
		name   string
		change func(*model.Credentials)
	}{
		{"wireguard private", func(c *model.Credentials) { c.PrivateKey = base64.StdEncoding.EncodeToString(make([]byte, 32)) }},
		{"wireguard public", func(c *model.Credentials) { c.EndpointPubKey = base64.StdEncoding.EncodeToString(make([]byte, 32)) }},
		{"wrong private curve", func(c *model.Credentials) { c.PrivateKey = base64.StdEncoding.EncodeToString(private) }},
		{"wrong public curve", func(c *model.Credentials) { c.EndpointPubKey = base64.StdEncoding.EncodeToString(public) }},
		{"no addresses", func(c *model.Credentials) { c.IPv4, c.IPv6 = "", "" }},
		{"ipv4 mislabeled", func(c *model.Credentials) { c.IPv4 = "2001:db8::1" }},
		{"ipv6 mislabeled", func(c *model.Credentials) { c.IPv6 = "192.0.2.1" }},
		{"mapped ipv6", func(c *model.Credentials) { c.IPv6 = "::ffff:192.0.2.1" }},
		{"cidr address", func(c *model.Credentials) { c.IPv4 = "192.0.2.1/32" }},
		{"invalid key", func(c *model.Credentials) { c.PrivateKey = "secret-invalid-key-material" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := base
			tc.change(&c)
			err := ValidateCredentials(c)
			if err == nil {
				t.Fatal("invalid credentials accepted")
			}
			for _, secret := range []string{c.PrivateKey, c.EndpointPubKey} {
				if secret != "" && strings.Contains(err.Error(), secret) {
					t.Fatal("validation error contains key material")
				}
			}
		})
	}
}

func TestEndpointPublicKeyPin(t *testing.T) {
	c, err := parseCredentials(testCredentials(t))
	if err != nil {
		t.Fatal(err)
	}
	config, err := outerTLS(c, "test.invalid")
	if err != nil {
		t.Fatal(err)
	}
	if err := config.VerifyConnection(tls.ConnectionState{}); err == nil {
		t.Fatal("missing peer certificate accepted")
	}
	if err := config.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{{PublicKey: c.public}}}); err != nil {
		t.Fatal(err)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := config.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{{PublicKey: &other.PublicKey}}}); err == nil {
		t.Fatal("wrong endpoint key accepted")
	}
}
