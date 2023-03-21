package shadowsocks

import (
	"fmt"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/common"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/infra/ip_mtu_trie"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/log"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server"
	"github.com/mzz2017/softwind/ciphers"
	"github.com/mzz2017/softwind/pool"
	"github.com/mzz2017/softwind/protocol"
	"github.com/mzz2017/softwind/protocol/shadowsocks"
	"io"
	"net"
	"strconv"
	"time"
)

func (s *Server) handleUDP(lAddr net.Addr, data []byte) (err error) {
	// get conn or dial and relay
	rc, passage, plainText, target, err := s.GetOrBuildUDPConn(lAddr, data)
	if err != nil {
		return fmt.Errorf("auth fail from: %v: %w", lAddr.String(), err)
	}
	defer pool.Put(plainText)

	// detect passage contention
	if err := s.ContentionCheck(lAddr.(*net.UDPAddr).IP, passage); err != nil {
		return err
	}

	targetAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return err
	}
	al, err := shadowsocks.BytesSizeForMetadata(plainText)
	if err != nil {
		return err
	}
	if _, err = rc.WriteTo(plainText[al:], targetAddr); err != nil {
		return fmt.Errorf("write error: %w", err)
	}
	return nil
}

// select an appropriate timeout
func selectTimeout(packet []byte) time.Duration {
	al, _ := shadowsocks.BytesSizeForMetadata(packet)
	if len(packet) < al {
		// err: packet with inadequate length
		return server.DefaultNatTimeout
	}
	packet = packet[al:]
	return server.SelectTimeout(packet)
}

// GetOrBuildUDPConn get a UDP conn from the mapping.
// plainText is from pool and starts with metadata. Please MUST put it back.
func (s *Server) GetOrBuildUDPConn(lAddr net.Addr, data []byte) (rc net.PacketConn, passage *Passage, plainText []byte, target string, err error) {
	var conn *UDPConn
	var ok bool

	// get user's context (preference)
	userContext := s.GetUserContextOrInsert(lAddr.(*net.UDPAddr).IP.String())

	buf := pool.Get(len(data))
	defer func() {
		if err != nil {
			pool.Put(buf)
		}
	}()
	// auth every key
	passage, plainText, err = s.authUDP(buf, data, userContext)
	if err != nil {
		return nil, nil, nil, "", err
	}
	targetMetadata, err := shadowsocks.NewMetadata(plainText)
	if err != nil {
		return nil, nil, nil, "", err
	}
	target = net.JoinHostPort(targetMetadata.Hostname, strconv.Itoa(int(targetMetadata.Port)))

	connIdent := lAddr.String()
	s.nm.Lock()
	if conn, ok = s.nm.Get(connIdent); !ok {
		// not exist such socket mapping, build one
		s.nm.Insert(connIdent, nil)
		s.nm.Unlock()

		// dial
		dialer := s.dialer
		if passage.Out != nil {
			sni, _ := common.HostToSNI(passage.Out.Host, s.sweetLisa.Host)
			dialer, err = protocol.NewDialer(string(passage.Out.Protocol), dialer, protocol.Header{
				ProxyAddress:    net.JoinHostPort(passage.Out.Host, passage.Out.Port),
				SNI:             sni,
				GrpcServiceName: common.SimplyGetParam(passage.Out.Method, "serviceName"),
				Cipher:          passage.Out.Method,
				Password:        passage.Out.Password,
				IsClient:        true,
				Flags:           0,
			})
			if err != nil {
				return nil, nil, nil, "", err
			}
		}
		c, err := dialer.Dial("udp", target)
		if err != nil {
			s.nm.Lock()
			s.nm.Remove(connIdent) // close channel to inform that establishment ends
			s.nm.Unlock()
			return nil, nil, nil, "", fmt.Errorf("GetOrBuildUDPConn dial error: %w", err)
		}
		rc = c.(net.PacketConn)
		s.nm.Lock()
		s.nm.Remove(connIdent) // close channel to inform that establishment ends
		conn = s.nm.Insert(connIdent, rc)
		conn.Timeout = selectTimeout(plainText)
		s.nm.Unlock()
		// relay
		go func() {
			if e := s.relay(lAddr, rc, conn.Timeout, *passage); e != nil {
				log.Trace("shadowsocks.udp.relay: %v", e)
			}
			s.nm.Lock()
			s.nm.Remove(connIdent)
			s.nm.Unlock()
		}()
	} else {
		// such socket mapping exists; just verify or wait for its establishment
		s.nm.Unlock()
		<-conn.Establishing
		if conn.PacketConn == nil {
			// establishment ended and retrieve the result
			return s.GetOrBuildUDPConn(lAddr, data)
		} else {
			// establishment succeeded
			rc = conn.PacketConn
		}
	}
	// countdown
	_ = conn.PacketConn.SetReadDeadline(time.Now().Add(conn.Timeout))
	return rc, passage, plainText, target, nil
}

func (s *Server) relay(laddr net.Addr, rConn net.PacketConn, timeout time.Duration, passage Passage) (err error) {
	var (
		n           int
		shadowBytes []byte
	)
	var mtu int
	if rConn.LocalAddr() != nil {
		mtu = ip_mtu_trie.MTUTrie.GetMTU(rConn.LocalAddr().(*net.UDPAddr).IP)
	} else {
		mtu = 1500
	}
	buf := pool.Get(BasicLen + mtu)
	defer pool.Put(buf)
	var inKey shadowsocks.Key
	inKey = shadowsocks.Key{
		CipherConf: ciphers.AeadCiphersConf[passage.In.Method],
		MasterKey:  passage.inMasterKey,
	}
	var (
		addr net.Addr
		sg   shadowsocks.SaltGenerator
	)
	for {
		_ = rConn.SetReadDeadline(time.Now().Add(timeout))
		n, addr, err = rConn.ReadFrom(buf)
		if err != nil {
			return fmt.Errorf("rConn.ReadFrom: %v", err)
		}
		_ = s.udpConn.SetWriteDeadline(time.Now().Add(server.DefaultNatTimeout)) // should keep consistent
		{
			// pack addr
			var sAddr *net.UDPAddr
			if addr == nil {
				//sAddr = rAddr
				log.Warn("relay(shadowsocks.udp): addr == nil")
			} else {
				sAddr = addr.(*net.UDPAddr)
			}

			var typ protocol.MetadataType
			if sAddr.AddrPort().Addr().Is4() {
				typ = protocol.MetadataTypeIPv4
			} else {
				typ = protocol.MetadataTypeIPv6
			}

			target := shadowsocks.Metadata{
				Metadata: protocol.Metadata{
					Type:     typ,
					Hostname: sAddr.IP.String(),
					Port:     uint16(sAddr.Port),
				},
			}

			b, err := target.BytesFromPool()
			if err != nil {
				log.Warn("relay: target.BytesFromPool: %v", err)
				return err
			}
			copy(buf[len(b):], buf[:n])
			copy(buf, b)
			n += len(b)
			pool.Put(b)
		}
		// FIXME: here does not use shadowsocks.NewUDPConn but it is okay
		sg, err = shadowsocks.GetSaltGenerator(inKey.MasterKey, inKey.CipherConf.SaltLen)
		if err != nil {
			log.Warn("relay: GetSaltGenerator: %v", err)
			continue
		}
		salt := sg.Get()
		shadowBytes, err = shadowsocks.EncryptUDPFromPool(inKey, buf[:n], salt)
		pool.Put(salt)
		if err != nil {
			log.Warn("relay: EncryptUDPFromPool: %v", err)
			continue
		}
		s.bloom.ExistOrAdd(shadowBytes[:inKey.CipherConf.SaltLen])
		_, err = s.udpConn.WriteTo(shadowBytes, laddr)
		if err != nil {
			pool.Put(shadowBytes)
			return
		}
		pool.Put(shadowBytes)
	}
}

func (s *Server) authUDP(buf []byte, data []byte, userContext *UserContext) (passage *Passage, content []byte, err error) {
	if len(data) < BasicLen {
		return nil, nil, io.ErrUnexpectedEOF
	}
	passage, content = userContext.Auth(func(passage *Passage) ([]byte, bool) {
		return probeUDP(buf, data, passage)
	})
	if passage == nil {
		return nil, nil, protocol.ErrFailAuth
	}
	// check bloom
	if exist := s.bloom.ExistOrAdd(data[:ciphers.AeadCiphersConf[passage.In.Method].SaltLen]); exist {
		return nil, nil, protocol.ErrReplayAttack
	}
	return passage, content, nil
}

func probeUDP(buf []byte, data []byte, server *Passage) (content []byte, ok bool) {
	//[salt][encrypted payload][tag]
	conf := ciphers.AeadCiphersConf[server.In.Method]
	if len(data) < conf.SaltLen+conf.TagLen {
		return nil, false
	}
	salt := data[:conf.SaltLen]
	cipherText := data[conf.SaltLen:]

	subKey := pool.Get(conf.KeyLen)[:0]
	defer pool.Put(subKey)
	b := subKey.Bytes()
	return conf.Verify(buf, server.inMasterKey, salt, cipherText, &b)
}
