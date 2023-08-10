package copyCert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

type certPair struct {
	originCert *x509.Certificate
	newCert    *x509.Certificate
	newCertPem []byte
	priv       interface{}
	privPem    []byte
}

func getCertsFromNetwork(addr string) ([]*x509.Certificate, error) {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}
	conn, err := tls.Dial("tcp", addr, conf)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates, nil
}

func reverse(s []*certPair) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}

func makeCerts(originCerts []*x509.Certificate) ([]*certPair, error) {
	certs := make([]*certPair, len(originCerts))
	// the origin order: website cert, intermediate ca, root ca
	for idx, cert := range originCerts {
		certs[idx] = &certPair{originCert: cert}
	}
	reverse(certs)

	for idx, pair := range certs {
		var pub interface{}
		switch pair.originCert.PublicKey.(type) {
		case *rsa.PublicKey:
			p, err := rsa.GenerateKey(rand.Reader, pair.originCert.PublicKey.(*rsa.PublicKey).Size()*8)
			if err != nil {
				return nil, fmt.Errorf("generate rsa key: %w", err)
			}
			pub = &p.PublicKey
			pair.priv = p
			pair.privPem = pem.EncodeToMemory(&pem.Block{Bytes: x509.MarshalPKCS1PrivateKey(p), Type: "RSA PRIVATE KEY"})
		case *ecdsa.PublicKey:
			p, err := ecdsa.GenerateKey(pair.originCert.PublicKey.(*ecdsa.PublicKey).Curve, rand.Reader)
			if err != nil {
				return nil, fmt.Errorf("generate ec key: %w", err)
			}
			pub = &p.PublicKey
			pair.priv = p
			data, err := x509.MarshalPKCS8PrivateKey(p)
			if err != nil {
				return nil, fmt.Errorf("MarshalPKCS8PrivateKey: %w", err)
			}
			pair.privPem = pem.EncodeToMemory(&pem.Block{Bytes: data, Type: "EC PRIVATE KEY"})
		default:
			return nil, fmt.Errorf("unknown key type: %T", pair.originCert.PublicKey)
		}
		// 10 years.
		pair.originCert.NotAfter = pair.originCert.NotBefore.AddDate(10, 0, 0)

		// remove the old public key (from the origin website cert)
		pair.originCert.PublicKey = nil
		// wo do not generate the root ca, the intermediate ca will be self-signed,
		// so the origin signature algorithm may be wrong
		pair.originCert.SignatureAlgorithm = x509.UnknownSignatureAlgorithm
		pair.newCert = pair.originCert
		var parent *certPair

		if idx > 0 {
			parent = certs[idx-1]
		} else {
			parent = pair
		}

		derBytes, err := x509.CreateCertificate(rand.Reader, pair.originCert, parent.newCert, pub, parent.priv)
		if err != nil {
			return nil, fmt.Errorf("CreateCertificate: %w", err)
		}
		pair.newCertPem = pem.EncodeToMemory(&pem.Block{Bytes: derBytes, Type: "CERTIFICATE"})
		cert, err := x509.ParseCertificate(derBytes)
		if err != nil {
			return nil, fmt.Errorf("ParseCertificate: %w", err)
		}
		pair.newCert = cert
	}
	return certs, nil
}

// addr is like github.com:443
func Copy(addr string) (c []byte, k []byte, err error) {
	certs, err := getCertsFromNetwork(addr)
	if err != nil {
		return nil, nil, err
	}
	newCerts, err := makeCerts(certs)
	if err != nil {
		return nil, nil, err
	}
	reverse(newCerts)

	var (
		bundleCerts bytes.Buffer
		bundleKeys  bytes.Buffer
	)
	for _, pair := range newCerts {
		bundleCerts.Write(pair.newCertPem)
		bundleKeys.Write(pair.privPem)
	}
	return bundleCerts.Bytes(), bundleKeys.Bytes(), nil
}
