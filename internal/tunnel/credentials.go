// The certificate profile follows usque v4.2.1 (github.com/Diniboy1123/usque).
// Copyright © 2025, github.com/Diniboy1123
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package tunnel

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"net/netip"
	"strings"
	"time"

	"fofa-masque/internal/model"
)

type credentials struct {
	private   *ecdsa.PrivateKey
	public    *ecdsa.PublicKey
	addresses []netip.Addr
}

// ValidateCredentials validates MASQUE device credentials, never echoing key material.
// WireGuard keys are not interchangeable with these ECDSA credentials.
func ValidateCredentials(c model.Credentials) error {
	_, err := parseCredentials(c)
	return err
}

func parseCredentials(c model.Credentials) (*credentials, error) {
	private, err := parsePrivateKey(strings.TrimSpace(c.PrivateKey))
	if err != nil {
		return nil, err
	}
	public, err := parsePublicKey(strings.TrimSpace(c.EndpointPubKey))
	if err != nil {
		return nil, err
	}
	addresses := make([]netip.Addr, 0, 2)
	for _, field := range []struct {
		name, value string
		ipv4        bool
	}{
		{"ipv4", c.IPv4, true}, {"ipv6", c.IPv6, false},
	} {
		value := strings.TrimSpace(field.value)
		if value == "" {
			continue
		}
		ip, err := netip.ParseAddr(value)
		if err != nil || ip.Zone() != "" || ip.Is4() != field.ipv4 || ip.Is4In6() || ip.IsUnspecified() || ip.IsMulticast() {
			return nil, errors.New(field.name + " must contain a valid unicast address of the named family (not a CIDR)")
		}
		addresses = append(addresses, ip)
	}
	if len(addresses) == 0 {
		return nil, errors.New("at least one assigned ipv4 or ipv6 address is required")
	}
	return &credentials{private: private, public: public, addresses: addresses}, nil
}

func parsePrivateKey(value string) (*ecdsa.PrivateKey, error) {
	const message = "private_key must be a P-256 ECDSA key: base64 SEC1 DER, PEM EC PRIVATE KEY, or unencrypted PEM PRIVATE KEY (PKCS8); WireGuard keys are not supported"
	var key *ecdsa.PrivateKey
	if block, rest := pem.Decode([]byte(value)); block != nil {
		if len(strings.TrimSpace(string(rest))) != 0 {
			return nil, errors.New(message)
		}
		switch block.Type {
		case "EC PRIVATE KEY":
			key, _ = x509.ParseECPrivateKey(block.Bytes)
		case "PRIVATE KEY":
			parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err == nil {
				key, _ = parsed.(*ecdsa.PrivateKey)
			}
		}
	} else if der, err := base64.StdEncoding.DecodeString(value); err == nil {
		key, _ = x509.ParseECPrivateKey(der)
	}
	if key == nil || key.Curve != elliptic.P256() {
		return nil, errors.New(message)
	}
	return key, nil
}

func parsePublicKey(value string) (*ecdsa.PublicKey, error) {
	const message = "endpoint_pub_key must be a P-256 ECDSA public key: PEM PUBLIC KEY or base64 PKIX DER; WireGuard keys are not supported"
	var der []byte
	if block, rest := pem.Decode([]byte(value)); block != nil {
		if block.Type != "PUBLIC KEY" || len(strings.TrimSpace(string(rest))) != 0 {
			return nil, errors.New(message)
		}
		der = block.Bytes
	} else {
		var err error
		der, err = base64.StdEncoding.DecodeString(value)
		if err != nil {
			return nil, errors.New(message)
		}
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, errors.New(message)
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New(message)
	}
	return key, nil
}

func outerTLS(c *credentials, sni string) (*tls.Config, error) {
	now := time.Now()
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(0), NotBefore: now, NotAfter: now.Add(24 * time.Hour),
	}, &x509.Certificate{}, &c.private.PublicKey, c.private)
	if err != nil {
		return nil, errors.New("could not generate the MASQUE client certificate")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		ServerName:   sni,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: c.private}},
		// This outer service uses an explicitly pinned key, not a public PKI name.
		// The inner HTTPS client uses Go's ordinary certificate verification.
		InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("MASQUE endpoint did not present a certificate")
			}
			key, ok := state.PeerCertificates[0].PublicKey.(*ecdsa.PublicKey)
			if !ok || !key.Equal(c.public) {
				return errors.New("MASQUE endpoint public key does not match endpoint_pub_key")
			}
			return nil
		},
	}, nil
}
