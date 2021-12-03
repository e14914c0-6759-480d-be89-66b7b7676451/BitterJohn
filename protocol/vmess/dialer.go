package vmess

import (
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/protocol"
	"github.com/google/uuid"
	"golang.org/x/net/proxy"
	"net"
)

func init() {
	protocol.Register("vmess", NewDialer)
}

type Dialer struct {
	proxyAddress string
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
	id, err := uuid.Parse(header.Password)
	if err != nil {
		return nil, err
	}
	//log.Trace("vmess.NewDialer: metadata: %v, password: %v", metadata, password)
	return &Dialer{
		nextDialer: nextDialer,
		metadata:   metadata,
		key:        NewID(id).CmdKey(),
	}, nil
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
