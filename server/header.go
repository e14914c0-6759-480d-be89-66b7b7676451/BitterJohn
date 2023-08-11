package server

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"

	"github.com/daeuniverse/softwind/protocol"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/common"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/config"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/SweetLisa/model"
)

func GetHeader(out model.Out, lisa *config.Lisa) (header *protocol.Header, err error) {
	var (
		sni       string
		feature1  string
		tlsConfig *tls.Config
		flags     protocol.Flags
	)
	switch out.Protocol {
	case protocol.ProtocolVMessTlsGrpc:
		feature1 = common.SimplyGetParam(out.Method, "serviceName")
		sni, _ = common.HostToSNI(out.Host, lisa.Host)
		flags = protocol.Flags_VMess_UsePacketAddr
	case protocol.ProtocolVMessTCP:
		flags = protocol.Flags_VMess_UsePacketAddr
	case protocol.ProtocolJuicity:
		feature1 = "bbr"
		pinnedHash, err := base64.URLEncoding.DecodeString(common.SimplyGetParam(out.Method, "pinned_certchain_sha256"))
		if err != nil {
			return nil, fmt.Errorf("decode pinned_certchain_sha256: %w", err)
		}
		sni = JuicityDomain
		tlsConfig = &tls.Config{
			NextProtos:         []string{"h3"},
			MinVersion:         tls.VersionTLS13,
			ServerName:         sni,
			InsecureSkipVerify: true,
			VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				if !bytes.Equal(common.GenerateCertChainHash(rawCerts), pinnedHash) {
					return fmt.Errorf("pinned hash of cert chain does not match")
				}
				return nil
			},
		}
	}
	return &protocol.Header{
		ProxyAddress: net.JoinHostPort(out.Host, out.Port),
		SNI:          sni,
		Feature1:     feature1,
		Cipher:       out.Method,
		User:         out.Username,
		Password:     out.Password,
		IsClient:     true,
		TlsConfig:    tlsConfig,
		Flags:        flags,
	}, nil
}
