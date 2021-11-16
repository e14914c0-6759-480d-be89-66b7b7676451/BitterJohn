package server

import (
	io2 "github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/zeroalloc/io"
	"net"
	"time"
)

type WriteCloser interface {
	CloseWrite() error
}

func RelayTCP(lConn, rConn net.Conn) (err error) {
	eCh := make(chan error, 1)
	go func() {
		_, e := io2.Copy(rConn, lConn)
		if rConn, ok := rConn.(WriteCloser); ok {
			rConn.CloseWrite()
		}
		rConn.SetReadDeadline(time.Now().Add(30 * time.Second))
		eCh <- e
	}()
	_, e := io2.Copy(lConn, rConn)
	if lConn, ok := lConn.(WriteCloser); ok {
		lConn.CloseWrite()
	}
	lConn.SetReadDeadline(time.Now().Add(30 * time.Second))
	if e != nil {
		<-eCh
		return e
	}
	return <-eCh
}
