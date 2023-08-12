package server

import (
	"sync"

	"github.com/daeuniverse/softwind/netproxy"
	"github.com/daeuniverse/softwind/protocol"
)

var (
	dialerMap   = map[string]netproxy.Dialer{}
	muDialerMap sync.Mutex
)

func NewDialer(name string, nextDialer netproxy.Dialer, header *protocol.Header) (netproxy.Dialer, error) {
	var err error
	switch name {
	case "juicity":
		// Cache dialer.
		muDialerMap.Lock()
		d, ok := dialerMap[header.ProxyAddress]
		if ok {
			muDialerMap.Unlock()
		} else {
			d, err = protocol.NewDialer(name, nextDialer, *header)
			if err != nil {
				muDialerMap.Unlock()
				return nil, err
			}
			dialerMap[header.ProxyAddress] = d
			muDialerMap.Unlock()
		}
		return d, nil
	default:
		return protocol.NewDialer(name, nextDialer, *header)
	}
}
