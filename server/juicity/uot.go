package juicity

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/daeuniverse/softwind/netproxy"
	"github.com/daeuniverse/softwind/pool"
	"github.com/daeuniverse/softwind/protocol/juicity"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/log"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server"
)

func relayConnToUDP(dst netproxy.PacketConn, src *juicity.PacketConn, timeout time.Duration, bufLen int) (err error) {
	var n int
	var addr netip.AddrPort
	buf := pool.GetFullCap(bufLen)
	defer pool.Put(buf)
	for {
		_ = src.SetReadDeadline(time.Now().Add(timeout))
		n, addr, err = src.ReadFrom(buf)
		if err != nil {
			return
		}
		_ = dst.SetWriteDeadline(time.Now().Add(server.DefaultNatTimeout)) // should keep consistent
		_, err = dst.WriteTo(buf[:n], addr.String())
		// WARNING: if the dst is an pre-connected conn, Write should be invoked here.
		if errors.Is(err, net.ErrWriteToConnected) {
			log.Error("relayConnToUDP: %v", err)
		}
		if err != nil {
			return
		}
	}
}

func relayUoT(rConn netproxy.PacketConn, lConn *juicity.PacketConn, bufLen int) (err error) {
	eCh := make(chan error, 1)
	go func() {
		e := relayConnToUDP(rConn, lConn, server.DefaultNatTimeout, bufLen)
		_ = rConn.SetReadDeadline(time.Now().Add(10 * time.Second))
		eCh <- e
	}()
	e := server.RelayUDPToConn(lConn, rConn, server.DefaultNatTimeout, bufLen)
	_ = lConn.CloseWrite()
	_ = lConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var netErr net.Error
	if errors.As(e, &netErr) && netErr.Timeout() {
		e = nil
	}
	e2 := <-eCh
	if errors.As(e2, &netErr) && netErr.Timeout() {
		e2 = nil
	}
	e = errors.Join(e, e2)
	if e != nil {
		return fmt.Errorf("RelayUDPToConn: %w", e)
	}
	return nil
}
