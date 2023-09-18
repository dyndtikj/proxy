package goproxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	mrand "math/rand"
	"net"
	"time"

	"github.com/patrickmn/go-cache"
)

var (
	rsaKeySize = 1024
	certTTL    = time.Hour * 24 * 365
)

type CaSigner struct {
	Ca    *tls.Certificate
	cache *cache.Cache
}

func NewCaSignerCache(defaultExpiration, cleanupInterval time.Duration) *CaSigner {
	c := cache.New(defaultExpiration, cleanupInterval)
	return &CaSigner{
		cache: c,
	}
}

func (c *CaSigner) SignHost(host string) (cert *tls.Certificate) {
	if host == "" {
		return
	}
	if value, ok := c.cache.Get(host); ok {
		if cert, ok = value.(*tls.Certificate); ok {
			return
		}
	}

	//cert, err := genCert(c.Ca, []string{host})
	cert, err := signHost(*c.Ca, host)
	if err != nil {
		return nil
	}

	c.cache.Set(host, cert, cache.DefaultExpiration)
	return
}

func signHost(ca tls.Certificate, host string) (*tls.Certificate, error) {
	x509ca, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		return nil, err
	}

	serial := hash(host)
	template := x509.Certificate{
		SerialNumber:          serial,
		Issuer:                x509ca.Subject,
		Subject:               x509ca.Subject,
		NotBefore:             time.Unix(0, 0),
		NotAfter:              time.Now().Add(certTTL),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	host = stripPort(host)
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else {
		template.DNSNames = append(template.DNSNames, host)
	}

	rnd := mrand.New(mrand.NewSource(serial.Int64()))
	certPriv, err := rsa.GenerateKey(rnd, rsaKeySize)
	if err != nil {
		return nil, err
	}
	derBytes, err := x509.CreateCertificate(rnd, &template, x509ca, &certPriv.PublicKey, ca.PrivateKey)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{derBytes, ca.Certificate[0]},
		PrivateKey:  certPriv,
	}, nil
}

const (
	caMaxAge   = 5 * 365 * 24 * time.Hour
	leafMaxAge = 24 * time.Hour
	caUsage    = x509.KeyUsageDigitalSignature |
		x509.KeyUsageContentCommitment |
		x509.KeyUsageKeyEncipherment |
		x509.KeyUsageDataEncipherment |
		x509.KeyUsageKeyAgreement |
		x509.KeyUsageCertSign |
		x509.KeyUsageCRLSign
	leafUsage = caUsage
)

func genCert(ca *tls.Certificate, names []string) (*tls.Certificate, error) {
	now := time.Now().Add(-1 * time.Hour).UTC()
	//if !ca.Leaf.IsCA {
	//	return nil, errors.New("CA cert is not a CA")
	//}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %s", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: names[0]},
		NotBefore:             now,
		NotAfter:              now.Add(leafMaxAge),
		KeyUsage:              leafUsage,
		BasicConstraintsValid: true,
		DNSNames:              names,
		SignatureAlgorithm:    x509.ECDSAWithSHA512,
	}
	key, err := genKeyPair()
	if err != nil {
		return nil, err
	}
	x, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Leaf, key.Public(), ca.PrivateKey)
	if err != nil {
		return nil, err
	}
	cert := new(tls.Certificate)
	cert.Certificate = append(cert.Certificate, x)
	cert.PrivateKey = key
	cert.Leaf, _ = x509.ParseCertificate(x)
	return cert, nil
}

func genKeyPair() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
}
