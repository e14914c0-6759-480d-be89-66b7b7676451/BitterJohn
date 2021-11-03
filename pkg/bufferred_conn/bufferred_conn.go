package bufferred_conn

import (
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/zeroalloc/bufio"
	"net"
)

type BufferedTCPConn struct {
	r        *bufio.Reader
	*net.TCPConn // So that most methods are embedded
}

func NewBufferedConn(c *net.TCPConn) BufferedTCPConn {
	return BufferedTCPConn{bufio.NewReader(c), c}
}

func NewBufferedConnSize(c *net.TCPConn, n int) BufferedTCPConn {
	return BufferedTCPConn{bufio.NewReaderSize(c, n), c}
}

func (b BufferedTCPConn) Peek(n int) ([]byte, error) {
	return b.r.Peek(n)
}

func (b BufferedTCPConn) Close() error {
	b.r.Put()
	return b.TCPConn.Close()
}

func (b BufferedTCPConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}
