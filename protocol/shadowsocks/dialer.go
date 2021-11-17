package shadowsocks

import (
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/protocol"
	"golang.org/x/net/proxy"
	"net"
)

func init() {
	protocol.Register("shadowsocks", NewDialer)
}

type Dialer struct {
	nextDialer proxy.Dialer
	metadata   protocol.Metadata
	key        []byte
}

func NewDialer(nextDialer proxy.Dialer, metadata protocol.Metadata, password string) (proxy.Dialer, error) {
	//log.Trace("shadowsocks.NewDialer: metadata: %v, password: %v", metadata, password)
	return &Dialer{
		nextDialer: nextDialer,
		metadata:   metadata,
		key:        EVPBytesToKey(password, CiphersConf[metadata.Cipher].KeyLen),
	}, nil
}

func (d *Dialer) Dial(network string, addr string) (c net.Conn, err error) {
	switch network {
	case "tcp":
		conn, err := d.nextDialer.Dial(network, addr)
		if err != nil {
			return nil, err
		}
		return NewTCPConn(conn, d.metadata, d.key, nil)
	case "udp":
		conn, err := d.nextDialer.Dial(network, addr)
		if err != nil {
			return nil, err
		}
		return NewUDPConn(conn.(net.PacketConn), d.metadata, d.key, nil)
	default:
		return nil, net.UnknownNetworkError(network)
	}
}
