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
	nextDialer proxy.Dialer
	metadata   protocol.Metadata
	key        []byte
}

func NewDialer(nextDialer proxy.Dialer, metadata protocol.Metadata, password string) (proxy.Dialer, error) {
	cipher, _ := ParseCipherFromSecurity(Cipher(metadata.Cipher).ToSecurity())
	metadata.Cipher = string(cipher)
	id, err := uuid.Parse(password)
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
		conn, err := d.nextDialer.Dial("tcp", addr)
		if err != nil {
			return nil, err
		}
		return NewConn(conn, Metadata{
			Metadata: d.metadata,
		}, d.key)
	default:
		return nil, net.UnknownNetworkError(network)
	}
}
