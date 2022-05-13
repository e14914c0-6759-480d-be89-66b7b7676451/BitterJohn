package grpc

import (
	"errors"
	"github.com/Qv2ray/gun/pkg/proto"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/log"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pool"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/protocol"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"io"
	"net"
	"sync"
	"time"
)

type ServerConn struct {
	localAddr net.Addr
	tun       proto.GunService_TunServer
	muReading sync.Mutex // muReading protects reading
	muWriting sync.Mutex // muWriting protects writing
	buf       []byte
	offset    int

	deadlineMu    sync.Mutex
	readDeadline  *time.Timer
	writeDeadline *time.Timer
	readClosed    bool
	writeClosed   bool
	closed        bool
}

func (c *ServerConn) Read(p []byte) (n int, err error) {
	c.deadlineMu.Lock()
	if c.readClosed || c.closed {
		c.deadlineMu.Unlock()
		return 0, io.EOF
	}
	c.deadlineMu.Unlock()

	c.muReading.Lock()
	defer c.muReading.Unlock()
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
		if code := status.Code(err); code == codes.Unavailable || status.Code(err) == codes.OutOfRange {
			err = io.EOF
		}
		return 0, err
	}
	n = copy(p, recv.Data)
	c.buf = pool.Get(len(recv.Data) - n)
	copy(c.buf, recv.Data[n:])
	c.offset = 0
	return n, nil
}

func (c *ServerConn) Write(p []byte) (n int, err error) {
	c.deadlineMu.Lock()
	if c.writeClosed || c.closed {
		c.deadlineMu.Unlock()
		return 0, io.EOF
	}
	c.deadlineMu.Unlock()

	c.muWriting.Lock()
	defer c.muWriting.Unlock()
	err = c.tun.Send(&proto.Hunk{Data: p})
	if code := status.Code(err); code == codes.Unavailable || status.Code(err) == codes.OutOfRange {
		err = io.EOF
	}
	return len(p), err
}

func (c *ServerConn) Close() error {
	c.closed = true
	return nil
}
func (c *ServerConn) LocalAddr() net.Addr {
	return c.localAddr
}
func (c *ServerConn) RemoteAddr() net.Addr {
	p, _ := peer.FromContext(c.tun.Context())
	return p.Addr
}

func (c *ServerConn) SetDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if now := time.Now(); t.After(now) {
		c.readClosed = false
		c.writeClosed = false
		if c.readDeadline != nil {
			c.readDeadline.Reset(t.Sub(now))
		} else {
			c.readDeadline = time.AfterFunc(t.Sub(now), func() {
				c.deadlineMu.Lock()
				defer c.deadlineMu.Unlock()
				c.readClosed = true
			})
		}
		if c.writeDeadline != nil {
			c.writeDeadline.Reset(t.Sub(now))
		} else {
			c.writeDeadline = time.AfterFunc(t.Sub(now), func() {
				c.deadlineMu.Lock()
				defer c.deadlineMu.Unlock()
				c.writeClosed = true
			})
		}
	} else {
		c.readClosed = true
		c.writeClosed = true
	}
	return nil
}

func (c *ServerConn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if now := time.Now(); t.After(now) {
		c.readClosed = false
		if c.readDeadline != nil {
			c.readDeadline.Reset(t.Sub(now))
		} else {
			c.readDeadline = time.AfterFunc(t.Sub(now), func() {
				c.deadlineMu.Lock()
				defer c.deadlineMu.Unlock()
				c.readClosed = true
			})
		}
	} else {
		c.readClosed = true
	}
	return nil
}

func (c *ServerConn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if now := time.Now(); t.After(now) {
		c.writeClosed = false
		if c.writeDeadline != nil {
			c.writeDeadline.Reset(t.Sub(now))
		} else {
			c.writeDeadline = time.AfterFunc(t.Sub(now), func() {
				c.deadlineMu.Lock()
				defer c.deadlineMu.Unlock()
				c.writeClosed = true
			})
		}
	} else {
		c.writeClosed = true
	}
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
