package shadowsocks

import "net"

func handleUDP(conn *net.UDPConn) error {
	return conn.Close()
}