package shadowsocks

import (
	"fmt"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/log"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pool"
	"golang.org/x/net/dns/dnsmessage"
	"net"
	"strconv"
	"time"
)

const (
	DefaultNatTimeout = 3 * time.Minute
	DnsQueryTimeout   = 17 * time.Second // RFC 5452
)

func (s *Server) handleUDP(lAddr net.Addr, data []byte, n int) (err error) {
	// get conn or dial and relay
	rc, key, plainText, err := s.GetOrBuildUCPConn(lAddr, data[:n])
	if err != nil {
		if err == ErrFailAuth {
			return nil
		}
		return fmt.Errorf("dial target error: %w", err)
	}

	size, _ := BytesSizeForMetadata(plainText)
	if key.forwardTo == "" {
		// send packet to target
		if _, err = rc.Write(plainText[size:]); err != nil {
			return fmt.Errorf("write error: %w", err)
		}
	} else {
		// send raw packet to the next ss server
		if _, err = rc.Write(data[:n]); err != nil {
			return fmt.Errorf("write error: %w", err)
		}
	}
	return nil
}

// select an appropriate timeout
func selectTimeout(packet []byte) time.Duration {
	al, _ := BytesSizeForMetadata(packet)
	if len(packet) < al {
		// err: packet with inadequate length
		return DefaultNatTimeout
	}
	packet = packet[al:]
	var dMessage dnsmessage.Message
	if err := dMessage.Unpack(packet); err != nil {
		return DefaultNatTimeout
	}
	return DnsQueryTimeout
}

func (s *Server) GetOrBuildUCPConn(lAddr net.Addr, data []byte) (rc *net.UDPConn, key *Key, plainText []byte, err error) {
	var conn *UDPConn
	var ok bool

	// get user's context (preference)
	userContext := s.GetUserContextOrInsert(lAddr.(*net.UDPAddr).IP.String())

	buf := pool.Get(len(data))
	defer pool.Put(buf)
	// auth every key
	key, plainText = s.authUDP(buf, data, userContext)
	if key == nil {
		return nil, nil, nil, ErrFailAuth
	}
	var target string
	var targetMetadata *Metadata
	if key.forwardTo == "" {
		targetMetadata, err = NewMetadata(plainText)
		if err != nil {
			return nil, nil, nil, err
		}
		target = net.JoinHostPort(targetMetadata.Hostname, strconv.Itoa(int(targetMetadata.Port)))
	} else {
		targetMetadata = nil
		target = key.forwardTo
	}

	connIdent := lAddr.String() + "<->" + target
	s.nm.Lock()
	if conn, ok = s.nm.Get(connIdent); !ok {
		// not exist such socket mapping, build one
		s.nm.Insert(connIdent, nil)
		s.nm.Unlock()

		// dial
		rConn, err := net.Dial("udp", target)
		if err != nil {
			s.nm.Lock()
			s.nm.Remove(connIdent) // close channel to inform that establishment ends
			s.nm.Unlock()
			return nil, nil, nil, fmt.Errorf("GetOrBuildUCPConn dial error: %w", err)
		}
		rc = rConn.(*net.UDPConn)
		s.nm.Lock()
		s.nm.Remove(connIdent) // close channel to inform that establishment ends
		conn = s.nm.Insert(connIdent, rc)
		conn.timeout = selectTimeout(plainText)
		s.nm.Unlock()
		// relay
		go func() {
			_ = relay(s.udpConn, lAddr, rc, conn.timeout, *key, targetMetadata)
			s.nm.Lock()
			s.nm.Remove(connIdent)
			s.nm.Unlock()
		}()
	} else {
		// such socket mapping exists; just verify or wait for its establishment
		s.nm.Unlock()
		<-conn.Establishing
		if conn.UDPConn == nil {
			// establishment ended and retrieve the result
			return s.GetOrBuildUCPConn(lAddr, data)
		} else {
			// establishment succeeded
			rc = conn.UDPConn
		}
	}
	// countdown
	_ = conn.UDPConn.SetReadDeadline(time.Now().Add(conn.timeout))
	return rc, key, plainText, nil
}

func relay(dst *net.UDPConn, laddr net.Addr, src *net.UDPConn, timeout time.Duration, k Key, target *Metadata) (err error) {
	var (
		n           int
		shadowBytes []byte
	)
	var bytesTarget []byte
	if target == nil {
		// forward to another ss server
		bytesTarget = nil
	} else {
		bytesTarget = target.BytesFromPool()
	}
	targetLen := len(bytesTarget)
	buf := pool.Get(targetLen + MTUTrie.GetMTU(src.LocalAddr().(*net.UDPAddr).IP))
	defer pool.Put(buf)
	copy(buf, bytesTarget)
	pool.Put(bytesTarget)
	for {
		_ = src.SetReadDeadline(time.Now().Add(timeout))
		n, _, err = src.ReadFrom(buf[targetLen:])
		if err != nil {
			return
		}
		_ = dst.SetWriteDeadline(time.Now().Add(DefaultNatTimeout)) // should keep consistent

		if target == nil {
			shadowBytes = buf[:targetLen+n]
		} else {
			shadowBytes, err = ShadowUDP(k, buf[:targetLen+n])
		}
		if err != nil {
			log.Warn("relay: ShadowUDP: %v", err)
			continue
		}
		_, err = dst.WriteTo(shadowBytes, laddr)
		if err != nil {
			pool.Put(shadowBytes)
			return
		}
		pool.Put(shadowBytes)
	}
}

func (s *Server) authUDP(buf []byte, data []byte, userContext *UserContext) (hit *Key, content []byte) {
	if len(data) < BasicLen {
		return nil, nil
	}
	return userContext.Auth(func(key Key) ([]byte, bool) {
		return probeUDP(buf, data, key)
	})
}

func probeUDP(buf []byte, data []byte, server Key) (content []byte, ok bool) {
	//[salt][encrypted payload][tag]
	conf := CiphersConf[server.method]
	if len(data) < conf.SaltLen+conf.TagLen {
		return nil, false
	}
	salt := data[:conf.SaltLen]
	cipherText := data[conf.SaltLen:]

	subKey := pool.Get(conf.KeyLen)[:0]
	defer pool.Put(subKey)
	return conf.Verify(buf, server.masterKey, salt, cipherText, &subKey)
}
