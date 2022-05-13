package grpc

import (
	"context"
	"fmt"
	"github.com/Qv2ray/gun/pkg/cert"
	"github.com/Qv2ray/gun/pkg/proto"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pool"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/SweetLisa/manager"
	"golang.org/x/net/proxy"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"io"
	"net"
	"sync"
	"time"
)

// https://github.com/v2fly/v2ray-core/blob/v5.0.6/transport/internet/grpc/dial.go
var (
	globalCCMap    map[string]*grpc.ClientConn
	globalCCAccess sync.Mutex
)

type ccCanceller func()

type ClientConn struct {
	tun       proto.GunService_TunClient
	closer    context.CancelFunc
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

func (c *ClientConn) Read(p []byte) (n int, err error) {
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
	if len(recv.Data) > n {
		c.buf = pool.Get(len(recv.Data) - n)
		copy(c.buf, recv.Data[n:])
		c.offset = 0
	}
	return n, nil
}

func (c *ClientConn) Write(p []byte) (n int, err error) {
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

func (c *ClientConn) Close() error {
	c.closed = true
	c.closer()
	return nil
}
func (c *ClientConn) CloseWrite() error {
	return c.tun.CloseSend()
}
func (c *ClientConn) LocalAddr() net.Addr {
	// FIXME
	return nil
}
func (c *ClientConn) RemoteAddr() net.Addr {
	p, _ := peer.FromContext(c.tun.Context())
	return p.Addr
}

func (c *ClientConn) SetDeadline(t time.Time) error {
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

func (c *ClientConn) SetReadDeadline(t time.Time) error {
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

func (c *ClientConn) SetWriteDeadline(t time.Time) error {
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

type Dialer struct {
	NextDialer  manager.Dialer
	ServiceName string
	ServerName  string
}

func (d *Dialer) Dial(network string, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func (d *Dialer) DialContext(ctx context.Context, network string, address string) (net.Conn, error) {
	cc, cancel, err := getGrpcClientConn(ctx, d.NextDialer, d.ServerName, address)
	if err != nil {
		cancel()
		return nil, err
	}
	client := proto.NewGunServiceClient(cc)

	clientX := client.(proto.GunServiceClientX)
	serviceName := d.ServiceName
	if serviceName == "" {
		serviceName = "GunService"
	}
	// ctx is the lifetime of the tun
	ctxStream, streamCloser := context.WithCancel(context.Background())
	tun, err := clientX.TunCustomName(ctxStream, serviceName)
	if err != nil {
		streamCloser()
		return nil, err
	}
	conn := ClientConn{tun: tun, closer: streamCloser}
	return &conn, nil
}

func getGrpcClientConn(ctx context.Context, dialer proxy.ContextDialer, serverName string, address string) (*grpc.ClientConn, ccCanceller, error) {
	globalCCAccess.Lock()
	defer globalCCAccess.Unlock()

	roots, err := cert.GetSystemCertPool()
	if err != nil {
		return nil, func() {}, fmt.Errorf("failed to get system certificate pool")
	}

	if globalCCMap == nil {
		globalCCMap = make(map[string]*grpc.ClientConn)
	}

	canceller := func() {
		globalCCAccess.Lock()
		defer globalCCAccess.Unlock()
		delete(globalCCMap, address)
	}

	// TODO Should support chain proxy to the same destination
	if client, found := globalCCMap[address]; found && client.GetState() != connectivity.Shutdown {
		return client, canceller, nil
	}
	cc, err := grpc.Dial(address,
		grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(roots, serverName)),
		grpc.WithContextDialer(func(ctxGrpc context.Context, s string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", s)
		}), grpc.WithConnectParams(grpc.ConnectParams{
			Backoff: backoff.Config{
				BaseDelay:  500 * time.Millisecond,
				Multiplier: 1.5,
				Jitter:     0.2,
				MaxDelay:   19 * time.Second,
			},
			MinConnectTimeout: 5 * time.Second,
		}),
	)
	globalCCMap[address] = cc
	return cc, canceller, err
}
