package shadowsocks

import (
	"bytes"
	"fmt"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/bufferredConn"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/log"
	io2 "github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/zeroalloc/io"
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
	BasicLen      = 32 + 2 + 16
	TCPBufferSize = 32 * 1024
)

var ErrPassageAbuse = fmt.Errorf("passage abuse")

func (s *Server) handleMsg(crw *SSConn, reqMetadata *Metadata, passage *Passage) error {
	if !passage.Manager {
		return fmt.Errorf("handleMsg: illegal message received from a non-manager passage")
	}
	if reqMetadata.Type != MetadataTypeMsg {
		return fmt.Errorf("handleMsg: this connection is not for message")
	}
	log.Trace("handleMsg: cmd: %v", reqMetadata.Cmd)

	// we know the body length but we should read all
	var req = pool.Get(int(reqMetadata.LenMsgBody))
	defer pool.Put(req)
	if _, err := io.ReadFull(crw, req); err != nil {
		return err
	}

	var respMeta = Metadata{
		Type: MetadataTypeMsg,
		Cmd:  MetadataCmdResponse,
	}
	var resp []byte
	var buf bytes.Buffer
	switch reqMetadata.Cmd {
	case MetadataCmdPing:
		if !bytes.Equal(req, []byte("ping")) {
			log.Warn("the body of received ping message is %v instead of %v", strconv.Quote(string(req)), strconv.Quote("ping"))
		}
		log.Trace("Received a ping message")
		s.lastAlive = time.Now()

		respMeta.LenMsgBody = 4
		bAddr := respMeta.BytesFromPool()
		defer pool.Put(bAddr)
		buf.Write(bAddr)

		resp = pool.Get(int(respMeta.LenMsgBody))
		defer pool.Put(resp)
		copy(resp, "pong")
	case MetadataCmdSyncPassages:
		var passages []model.Passage
		if err := jsoniter.Unmarshal(req, &passages); err != nil {
			return err
		}
		var serverPassages []server.Passage
		for _, passage := range passages {
			var user = server.Passage{
				Passage: passage,
				Manager: false,
			}
			serverPassages = append(serverPassages, user)
		}
		log.Info("Server asked to SyncPassages")
		// sweetLisa can replace the manager passage here
		if err := s.SyncPassages(serverPassages); err != nil {
			return err
		}

		respMeta.LenMsgBody = 2
		bAddr := respMeta.BytesFromPool()
		defer pool.Put(bAddr)
		buf.Write(bAddr)

		resp = pool.Get(int(respMeta.LenMsgBody))
		defer pool.Put(resp)
		copy(resp, "OK")
	default:
		return fmt.Errorf("%w: unexpected metadata cmd type: %v", ErrFailAuth, reqMetadata.Cmd)
	}

	buf.Write(resp)
	lenPadding := CalcPaddingLen(passage.inMasterKey, resp[len(resp)-int(respMeta.LenMsgBody):], false)
	if lenPadding > 0 {
		padding := pool.Get(lenPadding)
		defer pool.Put(padding)
		buf.Write(padding)
	}
	crw.Write(buf.Bytes())
	return nil
}

func (s *Server) handleTCP(conn net.Conn) error {
	bConn := bufferredConn.NewBufferedConnSize(conn, TCPBufferSize)
	passage, _ := s.authTCP(bConn)
	if passage == nil {
		// Auth fail. Drain the conn
		log.Info("Auth fail. Drain the conn from: %v", conn.RemoteAddr().String())
		_, err := io.Copy(io.Discard, conn)
		bConn.Close()
		return err
	}

	// detect passage contention
	contentionDuration := server.ProtectTime[passage.Use()]
	if contentionDuration > 0 {
		thisIP := conn.RemoteAddr().(*net.TCPAddr).IP
		passageKey := passage.In.Argument.Hash()
		accept, conflictIP := s.passageContentionCache.Check(passageKey, contentionDuration, thisIP)
		if !accept {
			bConn.Close()
			return fmt.Errorf("%w: from %v and %v: contention detected", ErrPassageAbuse, thisIP.String(), conflictIP.String())
		}
	}

	// handle connection
	var target string
	var lConn net.Conn
	crw, err := NewSSConn(bConn, CiphersConf[passage.In.Method], passage.inMasterKey)
	if err != nil {
		bConn.Close()
		return err
	}
	defer crw.Close()
	// Read target
	targetMetadata, err := crw.ReadMetadata()
	if err != nil {
		return err
	}
	if targetMetadata.Type == MetadataTypeMsg {
		return s.handleMsg(crw, targetMetadata, passage)
	}
	lConn = crw
	if passage.Out == nil {
		target = net.JoinHostPort(targetMetadata.Hostname, strconv.Itoa(int(targetMetadata.Port)))
	} else {
		target = net.JoinHostPort(passage.Out.Host, passage.Out.Port)
	}

	// manager should not come to this line
	if passage.Manager {
		return fmt.Errorf("%w: manager key is ubused for a non-cmd connection", ErrPassageAbuse)
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
	if passage.Out != nil {
		switch passage.Out.Protocol {
		case model.ProtocolShadowsocks:
			rConn, err = NewSSConn(rConn, CiphersConf[passage.Out.Method], passage.outMasterKey)
			if err != nil {
				return err
			}
			addr := targetMetadata.BytesFromPool()
			defer pool.Put(addr)
			if _, err = rConn.Write(addr); err != nil {
				rConn.Close()
				return err
			}
		}
	}
	if err = relayTCP(lConn, rConn); err != nil {
		if err, ok := err.(net.Error); ok && err.Timeout() {
			return nil // ignore i/o timeout
		}
		return fmt.Errorf("handleConn relay error: %w", err)
	}
	return nil
}

func relayTCP(lConn, rConn net.Conn) (err error) {
	defer rConn.Close()
	eCh := make(chan error, 1)
	go func() {
		_, e := io2.Copy(rConn, lConn)
		rConn.SetDeadline(time.Now())
		lConn.SetDeadline(time.Now())
		eCh <- e
	}()
	_, e := io2.Copy(lConn, rConn)
	rConn.SetDeadline(time.Now())
	lConn.SetDeadline(time.Now())
	if e != nil {
		return e
	}
	return <-eCh
}

func (s *Server) authTCP(conn bufferredConn.BufferedConn) (passage *Passage, err error) {
	var buf = pool.Get(BasicLen)
	defer pool.Put(buf)
	data, err := conn.Peek(BasicLen)
	if err != nil {
		return nil, io.ErrUnexpectedEOF
	}
	ctx := s.GetUserContextOrInsert(conn.RemoteAddr().(*net.TCPAddr).IP.String())
	passage, _ = ctx.Auth(func(passage Passage) ([]byte, bool) {
		return s.probeTCP(buf, data, passage)
	})
	return passage, nil
}

func (s *Server) probeTCP(buf []byte, data []byte, passage Passage) ([]byte, bool) {
	//[salt][encrypted payload length][length tag][encrypted payload][payload tag]
	conf := CiphersConf[passage.In.Method]

	salt := data[:conf.SaltLen]
	cipherText := data[conf.SaltLen : conf.SaltLen+2+conf.TagLen]

	return conf.Verify(buf, passage.inMasterKey, salt, cipherText, nil)
}
