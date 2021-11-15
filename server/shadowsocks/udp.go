package shadowsocks

import (
	"fmt"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/common"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/infra/ip_mtu_trie"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/log"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pool"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/protocol/shadowsocks"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server"
	"io"
	"net"
	"strconv"
	"time"
)

func (s *Server) handleUDP(lAddr net.Addr, data []byte) (err error) {
	// get conn or dial and relay
	rc, passage, plainText, target, err := s.GetOrBuildUCPConn(lAddr, data)
	if err != nil {
		return fmt.Errorf("auth fail from: %v: %w", lAddr.String(), err)
	}
	defer pool.Put(plainText)

	// detect passage contention
	if err := s.ContentionCheck(lAddr.(*net.UDPAddr).IP, passage); err != nil {
		return err
	}

	size, _ := shadowsocks.BytesSizeForMetadata(plainText)
	var toWrite []byte
	if passage.Out == nil {
		// send packet to target
		toWrite = plainText[size:]
	} else {
		// send encrypted packet to the next server
		if toWrite, err = shadowsocks.EncryptUDPFromPool(shadowsocks.Key{
			CipherConf: shadowsocks.CiphersConf[passage.Out.Method],
			MasterKey:  passage.outMasterKey,
		}, plainText); err != nil {
			return err
		}
		defer pool.Put(toWrite)
	}
	targetAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return err
	}
	if common.IsPrivate(targetAddr.IP) {
		return fmt.Errorf("%w: %v from %v", server.ErrDialPrivateAddress, targetAddr.String(), lAddr.String())
	}
	if _, err = rc.WriteToUDP(toWrite, targetAddr); err != nil {
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

// GetOrBuildUCPConn get a UDP conn from the mapping.
// plainText is from pool. Please MUST put it back.
func (s *Server) GetOrBuildUCPConn(lAddr net.Addr, data []byte) (rc *net.UDPConn, passage *Passage, plainText []byte, target string, err error) {
	var conn *shadowsocks.UDPConn
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
	if passage.Out == nil {
		target = net.JoinHostPort(targetMetadata.Hostname, strconv.Itoa(int(targetMetadata.Port)))
	} else {
		target = net.JoinHostPort(passage.Out.Host, passage.Out.Port)
	}

	connIdent := lAddr.String()
	s.nm.Lock()
	if conn, ok = s.nm.Get(connIdent); !ok {
		// not exist such socket mapping, build one
		s.nm.Insert(connIdent, nil)
		s.nm.Unlock()

		// dial
		rc, err = net.ListenUDP("udp", nil)
		if err != nil {
			s.nm.Lock()
			s.nm.Remove(connIdent) // close channel to inform that establishment ends
			s.nm.Unlock()
			return nil, nil, nil, "", fmt.Errorf("GetOrBuildUCPConn dial error: %w", err)
		}
		s.nm.Lock()
		s.nm.Remove(connIdent) // close channel to inform that establishment ends
		conn = s.nm.Insert(connIdent, rc)
		conn.Timeout = selectTimeout(plainText)
		s.nm.Unlock()
		// relay
		go func() {
			_ = s.relay(lAddr, rc, conn.Timeout, *passage)
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
	_ = conn.UDPConn.SetReadDeadline(time.Now().Add(conn.Timeout))
	return rc, passage, plainText, target, nil
}

func (s *Server) relay(laddr net.Addr, src *net.UDPConn, timeout time.Duration, passage Passage) (err error) {
	var (
		n           int
		shadowBytes []byte
	)
	buf := pool.Get(BasicLen + ip_mtu_trie.MTUTrie.GetMTU(src.LocalAddr().(*net.UDPAddr).IP))
	defer pool.Put(buf)
	var inKey, outKey shadowsocks.Key
	inKey = shadowsocks.Key{
		CipherConf: shadowsocks.CiphersConf[passage.In.Method],
		MasterKey:  passage.inMasterKey,
	}
	if passage.Out != nil {
		outKey = shadowsocks.Key{
			CipherConf: shadowsocks.CiphersConf[passage.Out.Method],
			MasterKey:  passage.outMasterKey,
		}
	}
	var addr net.Addr
	for {
		_ = src.SetReadDeadline(time.Now().Add(timeout))
		n, addr, err = src.ReadFrom(buf)
		if err != nil {
			return
		}
		_ = s.udpConn.SetWriteDeadline(time.Now().Add(server.DefaultNatTimeout)) // should keep consistent
		if passage.Out != nil {
			plainText, err := shadowsocks.DecryptUDP(outKey, buf[:n])
			if err != nil {
				log.Warn("relay: DecryptUDP: %v", err)
				continue
			}
			n = len(plainText)
		} else {
			sAddr := addr.(*net.UDPAddr)
			var typ shadowsocks.MetadataType
			if sAddr.IP.To4() != nil {
				typ = shadowsocks.MetadataTypeIPv4
			} else {
				typ = shadowsocks.MetadataTypeIPv6
			}
			target := shadowsocks.Metadata{
				Type:     typ,
				Hostname: sAddr.IP.String(),
				Port:     uint16(sAddr.Port),
			}
			b := target.BytesFromPool()
			copy(buf[len(b):], buf[:n])
			copy(buf, b)
			n += len(b)
			pool.Put(b)
		}
		shadowBytes, err = shadowsocks.EncryptUDPFromPool(inKey, buf[:n])
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
	passage, content = userContext.Auth(func(passage Passage) ([]byte, bool) {
		return probeUDP(buf, data, passage)
	})
	if passage == nil {
		return nil, nil, server.ErrFailAuth
	}
	// check bloom
	if exist := s.bloom.ExistOrAdd(data[:shadowsocks.CiphersConf[passage.In.Method].SaltLen]); exist {
		return nil, nil, server.ErrReplayAttack
	}
	return passage, content, nil
}

func probeUDP(buf []byte, data []byte, server Passage) (content []byte, ok bool) {
	//[salt][encrypted payload][tag]
	conf := shadowsocks.CiphersConf[server.In.Method]
	if len(data) < conf.SaltLen+conf.TagLen {
		return nil, false
	}
	salt := data[:conf.SaltLen]
	cipherText := data[conf.SaltLen:]

	subKey := pool.Get(conf.KeyLen)[:0]
	defer pool.Put(subKey)
	return conf.Verify(buf, server.inMasterKey, salt, cipherText, &subKey)
}
