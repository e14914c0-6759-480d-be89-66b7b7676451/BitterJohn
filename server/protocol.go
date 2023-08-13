package server

import (
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/softwind/netproxy"
	"github.com/daeuniverse/softwind/protocol"
)

const (
	evictLifeWindow = 10 * time.Minute
)

type evictableDialer struct {
	netproxy.Dialer
	t *time.Timer
}

var (
	dialerMap   = map[string]*evictableDialer{}
	muDialerMap sync.Mutex
)

func NewDialer(name string, nextDialer netproxy.Dialer, header *protocol.Header) (netproxy.Dialer, error) {
	switch name {
	case "juicity":
		// Cache dialer.
		key := strings.Join([]string{
			header.ProxyAddress,
			header.User,
			header.Password,
			header.Cipher,
			header.SNI,
			strconv.Itoa(int(header.Flags)),
			header.Feature1,
		}, ":")
		muDialerMap.Lock()
		ed, ok := dialerMap[key]
		if ok {
			ed.t.Reset(evictLifeWindow)
			muDialerMap.Unlock()
		} else {
			dialer, err := protocol.NewDialer(name, nextDialer, *header)
			if err != nil {
				muDialerMap.Unlock()
				return nil, err
			}
			ed = &evictableDialer{
				Dialer: dialer,
				t: time.AfterFunc(evictLifeWindow, func() {
					muDialerMap.Lock()
					if ed, ok := dialerMap[key]; ok && ed == dialer {
						delete(dialerMap, key)
					}
					muDialerMap.Unlock()
				}),
			}
			dialerMap[key] = ed
			muDialerMap.Unlock()
		}
		return ed.Dialer, nil
	default:
		return protocol.NewDialer(name, nextDialer, *header)
	}
}
