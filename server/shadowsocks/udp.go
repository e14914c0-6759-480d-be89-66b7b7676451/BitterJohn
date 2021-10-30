package shadowsocks

import (
	"fmt"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/log"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pool"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/SweetLisa/model"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"net"
	"strconv"
	"time"
)

const (
	DefaultNatTimeout = 3 * time.Minute
	DnsQueryTimeout   = 17 * time.Second // RFC 5452
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

	size, _ := BytesSizeForMetadata(plainText)
	var toWrite []byte
	if passage.Out == nil {
		// send packet to target
		toWrite = plainText[size:]
	} else {
		// send encrypted packet to the next server
		if toWrite, err = EncryptUDPFromPool(Key{
			CipherConf: CiphersConf[passage.Out.Method],
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
	if _, err = rc.WriteToUDP(toWrite, targetAddr); err != nil {
		return fmt.Errorf("write error: %w", err)
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

// GetOrBuildUCPConn get a UDP conn from the mapping.
// plainText is from pool. Please MUST put it back.
func (s *Server) GetOrBuildUCPConn(lAddr net.Addr, data []byte) (rc *net.UDPConn, passage *Passage, plainText []byte, target string, err error) {
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
	targetMetadata, err := NewMetadata(plainText)
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
		conn.timeout = selectTimeout(plainText)
		s.nm.Unlock()
		// relay
		go func() {
			_ = relay(s.udpConn, lAddr, rc, conn.timeout, *passage)
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
	return rc, passage, plainText, target, nil
}

func relay(dst *net.UDPConn, laddr net.Addr, src *net.UDPConn, timeout time.Duration, passage Passage) (err error) {
	var (
		n           int
		shadowBytes []byte
	)
	buf := pool.Get(BasicLen + MTUTrie.GetMTU(src.LocalAddr().(*net.UDPAddr).IP))
	defer pool.Put(buf)
	var inKey, outKey Key
	inKey = Key{
		CipherConf: CiphersConf[passage.In.Method],
		MasterKey:  passage.inMasterKey,
	}
	if passage.Out != nil {
		switch passage.Out.Protocol {
		case model.ProtocolShadowsocks:
			outKey = Key{
				CipherConf: CiphersConf[passage.Out.Method],
				MasterKey:  passage.outMasterKey,
			}
		}
	}
	var addr net.Addr
	for {
		_ = src.SetReadDeadline(time.Now().Add(timeout))
		n, addr, err = src.ReadFrom(buf)
		if err != nil {
			return
		}
		_ = dst.SetWriteDeadline(time.Now().Add(DefaultNatTimeout)) // should keep consistent
		if passage.Out != nil {
			plainText, err := DecryptUDP(outKey, buf[:n])
			if err != nil {
				log.Warn("relay: DecryptUDP: %v", err)
				continue
			}
			n = len(plainText)
		} else {
			sAddr := addr.(*net.UDPAddr)
			var typ MetadataType
			if sAddr.IP.To4() != nil {
				typ = MetadataTypeIPv4
			} else {
				typ = MetadataTypeIPv6
			}
			target := Metadata{
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
		shadowBytes, err = EncryptUDPFromPool(inKey, buf[:n])
		if err != nil {
			log.Warn("relay: EncryptUDPFromPool: %v", err)
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

func (s *Server) authUDP(buf []byte, data []byte, userContext *UserContext) (passage *Passage, content []byte, err error) {
	if len(data) < BasicLen {
		return nil, nil, io.ErrUnexpectedEOF
	}
	passage, content = userContext.Auth(func(passage Passage) ([]byte, bool) {
		return probeUDP(buf, data, passage)
	})
	if passage == nil {
		return nil, nil, ErrFailAuth
	}
	// check bloom
	if exist := s.bloom.ExistOrAdd(data[:CiphersConf[passage.In.Method].SaltLen]); exist {
		return nil, nil, ErrReplayAttack
	}
	return passage, content, nil
}

func probeUDP(buf []byte, data []byte, server Passage) (content []byte, ok bool) {
	//[salt][encrypted payload][tag]
	conf := CiphersConf[server.In.Method]
	if len(data) < conf.SaltLen+conf.TagLen {
		return nil, false
	}
	salt := data[:conf.SaltLen]
	cipherText := data[conf.SaltLen:]

	subKey := pool.Get(conf.KeyLen)[:0]
	defer pool.Put(subKey)
	return conf.Verify(buf, server.inMasterKey, salt, cipherText, &subKey)
}
