package vmess

import (
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/common"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/protocol"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/SweetLisa/manager"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/SweetLisa/model"
	"github.com/google/uuid"
	"golang.org/x/net/proxy"
	"net"
)

func init() {
	protocol.Register("vmess", NewDialerFactory(model.ProtocolVMessTCP))
	protocol.Register("vmess+tls+grpc", NewDialerFactory(model.ProtocolVMessTlsGrpc))
}

type Dialer struct {
	protocol     model.Protocol
	proxyAddress string
	proxySNI     string
	nextDialer   proxy.Dialer
	metadata     protocol.Metadata
	key          []byte
}

func NewDialer(nextDialer proxy.Dialer, header protocol.Header) (proxy.Dialer, error) {
	metadata := protocol.Metadata{
		IsClient: header.IsClient,
	}
	cipher, _ := ParseCipherFromSecurity(Cipher(header.Cipher).ToSecurity())
	metadata.Cipher = string(cipher)

	// UUID mapping
	if l := len([]byte(header.Password)); l < 32 || l > 36 {
		header.Password = common.StringToUUID5(header.Password)
	}

	id, err := uuid.Parse(header.Password)
	if err != nil {
		return nil, err
	}
	//log.Trace("vmess.NewDialer: metadata: %v, password: %v", metadata, password)
	return &Dialer{
		proxyAddress: header.ProxyAddress,
		proxySNI:     header.SNI,
		nextDialer:   nextDialer,
		metadata:     metadata,
		key:          NewID(id).CmdKey(),
	}, nil
}

func NewDialerFactory(proto model.Protocol) func(nextDialer proxy.Dialer, header protocol.Header) (proxy.Dialer, error) {
	return func(nextDialer proxy.Dialer, header protocol.Header) (proxy.Dialer, error) {
		d, err := NewDialer(nextDialer, header)
		if err != nil {
			return nil, err
		}
		dd := d.(*Dialer)
		dd.protocol = proto
		return dd, nil
	}
}

func (d *Dialer) Dial(network string, addr string) (c net.Conn, err error) {
	switch network {
	case "tcp", "udp":
		mdata, err := protocol.ParseMetadata(addr)
		if err != nil {
			return nil, err
		}
		mdata.Cipher = d.metadata.Cipher
		mdata.IsClient = d.metadata.IsClient

		if d.protocol == model.ProtocolVMessTlsGrpc {
			d.nextDialer = &GrpcDialer{
				NextDialer: &manager.DialerConverter{Dialer: d.nextDialer},
				ServerName: d.proxySNI,
			}
		}

		conn, err := d.nextDialer.Dial("tcp", d.proxyAddress)
		if err != nil {
			return nil, err
		}

		return NewConn(conn, Metadata{
			Metadata: mdata,
			Network:  network,
		}, d.key)
	default:
		return nil, net.UnknownNetworkError(network)
	}
}
