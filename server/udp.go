package server

import (
	"net"
	"time"

	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/infra/ip_mtu_trie"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pool"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	DefaultNatTimeout = 3 * time.Minute
	DnsQueryTimeout   = 17 * time.Second // RFC 5452
)

// SelectTimeout selects an appropriate timeout for UDP packet.
func SelectTimeout(packet []byte) time.Duration {
	var dMessage dnsmessage.Message
	if err := dMessage.Unpack(packet); err != nil {
		return DefaultNatTimeout
	}
	return DnsQueryTimeout
}

func RelayUDP(dst *net.UDPConn, laddr net.Addr, src net.PacketConn, timeout time.Duration) (err error) {
	var n int
	buf := pool.Get(ip_mtu_trie.MTUTrie.GetMTU(src.LocalAddr().(*net.UDPAddr).IP))
	defer pool.Put(buf)
	for {
		_ = src.SetReadDeadline(time.Now().Add(timeout))
		n, _, err = src.ReadFrom(buf)
		if err != nil {
			return
		}
		_ = dst.SetWriteDeadline(time.Now().Add(DefaultNatTimeout)) // should keep consistent
		_, err = dst.WriteTo(buf[:n], laddr)
		if err != nil {
			return
		}
	}
}

func RelayUDPToConn(dst net.Conn, src net.PacketConn, timeout time.Duration) (err error) {
	var n int
	var addr net.Addr
	buf := pool.Get(ip_mtu_trie.MTUTrie.GetMTU(src.LocalAddr().(*net.UDPAddr).IP))
	defer pool.Put(buf)
	for {
		_ = src.SetReadDeadline(time.Now().Add(timeout))
		n, addr, err = src.ReadFrom(buf)
		if err != nil {
			return
		}
		_ = dst.SetWriteDeadline(time.Now().Add(DefaultNatTimeout)) // should keep consistent
		_, err = dst.(interface {
			WriteTo(p []byte, addr net.Addr) (n int, err error)
		}).WriteTo(buf[:n], addr)
		if err != nil {
			return
		}
	}
}
