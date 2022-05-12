package grpc

import (
	"errors"
	"github.com/Qv2ray/gun/pkg/proto"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/log"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pool"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/protocol"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server"
	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"
	"net"
	"sync"
	"time"
)

type ServerConn struct {
	localAddr net.Addr
	tun       proto.GunService_TunServer
	mu        sync.Mutex // mu protects reading
	buf       []byte
	offset    int
}

func (c *ServerConn) Read(p []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.buf != nil {
		n = copy(p, c.buf[c.offset:])
		c.offset += n
		if c.offset == len(c.buf) {
			pool.Put(c.buf)
			c.buf = nil
		}
		return n, nil
	}
	recv, err := c.tun.Recv()
	if err != nil {
		return 0, err
	}
	n = copy(p, recv.Data)
	c.buf = pool.Get(len(recv.Data) - n)
	copy(c.buf, recv.Data[n:])
	c.offset = 0
	return n, nil
}

func (c *ServerConn) Write(p []byte) (n int, err error) {
	return len(p), c.tun.Send(&proto.Hunk{Data: p})
}

func (c *ServerConn) Close() error {
	return nil
}
func (c *ServerConn) LocalAddr() net.Addr {
	return c.localAddr
}
func (c *ServerConn) RemoteAddr() net.Addr {
	p, _ := peer.FromContext(c.tun.Context())
	return p.Addr
}

// SetDeadline is not implemented
func (c *ServerConn) SetDeadline(t time.Time) error {
	return nil
}

// SetReadDeadline is not implemented
func (c *ServerConn) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline is not implemented
func (c *ServerConn) SetWriteDeadline(t time.Time) error {
	return nil
}


type Server struct {
	*grpc.Server
	LocalAddr  net.Addr
	HandleConn func(conn net.Conn) error
}

func (g Server) Tun(tun proto.GunService_TunServer) error {
	if err := g.HandleConn(&ServerConn{
		localAddr: g.LocalAddr,
		tun:       tun,
	}); err != nil {
		if errors.Is(err, server.ErrPassageAbuse) ||
			errors.Is(err, protocol.ErrReplayAttack) {
			log.Warn("handleConn: %v", err)
		} else {
			log.Info("handleConn: %v", err)
		}
		return err
	}
	return nil
}

func (g Server) TunDatagram(datagramServer proto.GunService_TunDatagramServer) error {
	return nil
}