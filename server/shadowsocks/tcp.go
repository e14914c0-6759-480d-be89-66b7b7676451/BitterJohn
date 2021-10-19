package shadowsocks

import (
	"bytes"
	"fmt"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/bufferredConn"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/log"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pool"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/SweetLisa/model"
	jsoniter "github.com/json-iterator/go"
	"io"
	"net"
	"strconv"
	"time"
)

const (
	// BasicLen is the basic auth length of [salt][encrypted payload length][length tag][encrypted payload][payload tag]
	BasicLen = 32 + 2 + 16
)

func (s *Server) handleMsg(crw *SSConn, reqMetadata *Metadata, key *Key) error {
	if !key.manager {
		return fmt.Errorf("handleMsg: illegal message received from a non-manager user")
	}
	if reqMetadata.Type != MetadataTypeMsg {
		return fmt.Errorf("handleMsg: this connection is not for message")
	}
	// we know the body length but we should read all
	var req = pool.Get(int(reqMetadata.LenMsgBody))
	defer pool.Put(req)
	if _, err := io.ReadFull(crw, req); err != nil {
		return err
	}
	lenPadding := CalcPaddingLen(key.masterKey, req, true)
	var padding = pool.Get(lenPadding)
	defer pool.Put(padding)
	if _, err := io.ReadFull(crw, padding); err != nil {
		return err
	}

	var respMeta = Metadata{
		Type: MetadataTypeMsg,
		Cmd:  MetadataCmdResponse,
	}
	var resp []byte
	switch reqMetadata.Cmd {
	case MetadataCmdPing:
		if !bytes.Equal(req, []byte("ping")) {
			log.Warn("the body of received ping message is %v instead of %v", strconv.Quote(string(req)), strconv.Quote("ping"))
		}
		s.lastAlive = time.Now()

		respMeta.LenMsgBody = 4
		bAddr := respMeta.BytesFromPool()
		defer pool.Put(bAddr)
		crw.Write(bAddr)

		resp = pool.Get(int(respMeta.LenMsgBody))
		defer pool.Put(resp)
		copy(resp, "pong")
	case MetadataCmdSyncKeys:
		var keys []model.Server
		if err := jsoniter.Unmarshal(req, &keys); err != nil {
			return err
		}
		var serverUsers []server.User
		for _, u := range keys {
			var user = server.User{
				Username: u.Argument.Username,
				Password: u.Argument.Password,
				Method:   u.Argument.Method,
				Manager:  false,
			}
			if u.Host != "" {
				user.ForwardTo = net.JoinHostPort(u.Host, strconv.Itoa(u.Port))
			}
			serverUsers = append(serverUsers, user)
		}
		// sweetLisa can replace the manager key here
		if err := s.syncUsers(serverUsers); err != nil {
			return err
		}

		respMeta.LenMsgBody = 2
		bAddr := respMeta.BytesFromPool()
		defer pool.Put(bAddr)
		crw.Write(bAddr)

		resp = pool.Get(int(respMeta.LenMsgBody))
		defer pool.Put(resp)
		copy(resp, "OK")
	default:
		return fmt.Errorf("%w: unexpected metadata cmd type: %v", ErrFailAuth, reqMetadata.Cmd)
	}

	crw.Write(resp)
	padding = pool.Get(CalcPaddingLen(key.masterKey, resp, false))
	defer pool.Put(padding)
	crw.Write(padding)
	return nil
}

func (s *Server) handleTCP(conn net.Conn) error {
	bConn := bufferredConn.NewBufferedConnSize(conn, MTUTrie.GetMTU(conn.LocalAddr().(*net.TCPAddr).IP))
	defer bConn.Close()
	key, _ := s.authTCP(bConn)
	if key == nil {
		// Auth fail. Drain the conn
		log.Info("Auth fail. Drain the conn from: %v", conn.RemoteAddr().String())
		_, err := io.Copy(io.Discard, conn)
		return err
	}
	var target string
	var lConn net.Conn
	if key.forwardTo == "" {
		crw, err := NewSSConn(bConn, CiphersConf[key.method], key.masterKey)
		if err != nil {
			return err
		}
		// Read target
		targetMetadata, err := crw.ReadMetadata()
		if err != nil {
			return err
		}
		if targetMetadata.Type == MetadataTypeMsg {
			return s.handleMsg(crw, targetMetadata, key)
		}
		lConn = crw
		target = net.JoinHostPort(targetMetadata.Hostname, strconv.Itoa(int(targetMetadata.Port)))
	} else {
		lConn = bConn
		target = key.forwardTo
	}

	// Dial and relay
	rConn, err := net.Dial("tcp", target)
	if err != nil {
		if err, ok := err.(net.Error); ok && err.Timeout() {
			log.Debug("%v", err)
			return nil // ignore i/o timeout
		}
		return err
	}
	if err = relayTCP(lConn, rConn); err != nil {
		if err, ok := err.(net.Error); ok && err.Timeout() {
			return nil // ignore i/o timeout
		}
		return fmt.Errorf("[tcp] handleConn relay error: %w", err)
	}
	return nil
}

func relayTCP(lConn, rConn net.Conn) (err error) {
	defer rConn.Close()
	eCh := make(chan error, 1)
	go func() {
		_, e := io.Copy(rConn, lConn)
		rConn.SetDeadline(time.Now())
		lConn.SetDeadline(time.Now())
		eCh <- e
	}()
	_, e := io.Copy(lConn, rConn)
	rConn.SetDeadline(time.Now())
	lConn.SetDeadline(time.Now())
	if e != nil {
		return e
	}
	return <-eCh
}

func (s *Server) authTCP(conn bufferredConn.BufferedConn) (key *Key, err error) {
	var buf = pool.Get(BasicLen)
	defer pool.Put(buf)
	data, err := conn.Peek(BasicLen)
	if err != nil {
		return nil, io.ErrUnexpectedEOF
	}
	ctx := s.GetUserContextOrInsert(conn.RemoteAddr().(*net.TCPAddr).IP.String())
	key, _ = ctx.Auth(func(key Key) ([]byte, bool) {
		return s.probeTCP(buf, data, key)
	})
	return key, nil
}

func (s *Server) probeTCP(buf []byte, data []byte, key Key) ([]byte, bool) {
	//[salt][encrypted payload length][length tag][encrypted payload][payload tag]
	conf := CiphersConf[key.method]

	salt := data[:conf.SaltLen]
	cipherText := data[conf.SaltLen : conf.SaltLen+2+conf.TagLen]

	return conf.Verify(buf, key.masterKey, salt, cipherText, nil)
}
