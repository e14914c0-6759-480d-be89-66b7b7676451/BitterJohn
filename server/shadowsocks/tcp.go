package shadowsocks

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/bufferred_conn"
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
	BasicLen      = 32 + 2 + 16
	TCPBufferSize = 32 * 1024
)

func (s *Server) handleMsg(crw *TCPConn, reqMetadata *Metadata, passage *Passage) error {
	if !passage.Manager {
		return fmt.Errorf("handleMsg: illegal message received from a non-manager passage")
	}
	if reqMetadata.Type != MetadataTypeMsg {
		return fmt.Errorf("handleMsg: this connection is not for message")
	}
	log.Trace("handleMsg: cmd: %v", reqMetadata.Cmd)

	// we know the body length but we should read all
	var req = pool.Get(int(reqMetadata.LenMsgBody & 0xfffff))
	defer pool.Put(req)
	if _, err := io.ReadFull(crw, req); err != nil {
		return err
	}

	var respMeta = Metadata{
		Type: MetadataTypeMsg,
		Cmd:  server.MetadataCmdResponse,
	}
	var resp []byte
	var buf bytes.Buffer
	switch reqMetadata.Cmd {
	case server.MetadataCmdPing:
		if !bytes.Equal(req, []byte("ping")) {
			log.Warn("the body of received ping message is %v instead of %v", strconv.Quote(string(req)), strconv.Quote("ping"))
		}
		log.Trace("Received a ping message")
		s.lastAlive = time.Now()
		bandwidthLimit, err := server.GenerateBandwidthLimit()
		if err != nil {
			log.Warn("generatePingResp: %v", err)
			return err
		}
		bPingResp, err := jsoniter.Marshal(model.PingResp{BandwidthLimit: bandwidthLimit})
		if err != nil {
			log.Warn("%v", err)
			return err
		}

		respMeta.LenMsgBody = uint32(len(bPingResp))
		bAddr := respMeta.BytesFromPool()
		defer pool.Put(bAddr)
		buf.Write(bAddr)

		resp = bPingResp
	case server.MetadataCmdSyncPassages:
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
		return fmt.Errorf("%w: unexpected metadata cmd type: %v", server.ErrFailAuth, reqMetadata.Cmd)
	}

	buf.Write(resp)
	lenPadding := CalcPaddingLen(passage.inMasterKey, resp[len(resp)-int(respMeta.LenMsgBody):], false)
	if lenPadding > 0 {
		padding := pool.Get(lenPadding)
		defer pool.Put(padding)
		buf.Write(padding)
	}
	_, err := crw.Write(buf.Bytes())
	return err
}

func (s *Server) handleTCP(conn net.Conn) error {
	bConn := bufferred_conn.NewBufferedConnSize(conn.(*net.TCPConn), TCPBufferSize)
	passage, err := s.authTCP(bConn)
	if err != nil {
		// Auth fail. Drain the conn
		io.Copy(io.Discard, bConn)
		bConn.Close()
		return fmt.Errorf("auth fail: %w. Drained the conn from: %v", err, conn.RemoteAddr().String())
	}

	// detect passage contention
	if err := s.ContentionCheck(conn.RemoteAddr().(*net.TCPAddr).IP, passage); err != nil {
		io.Copy(io.Discard, bConn)
		bConn.Close()
		return err
	}

	// handle connection
	var target string
	lConn, err := NewTCPConn(bConn, CiphersConf[passage.In.Method], passage.inMasterKey, s.bloom)
	if err != nil {
		bConn.Close()
		return err
	}
	defer lConn.Close()
	// Read target
	targetMetadata, err := lConn.ReadMetadata()
	if err != nil {
		return err
	}
	if targetMetadata.Type == MetadataTypeMsg {
		return s.handleMsg(lConn, targetMetadata, passage)
	}
	if passage.Out == nil {
		target = net.JoinHostPort(targetMetadata.Hostname, strconv.Itoa(int(targetMetadata.Port)))
	} else {
		target = net.JoinHostPort(passage.Out.Host, passage.Out.Port)
	}

	// manager should not come to this line
	if passage.Manager {
		return fmt.Errorf("%w: manager key is ubused for a non-cmd connection", server.ErrPassageAbuse)
	}

	// Dial and relay
	rConn, err := server.DefaultLimitedDialer.Dial("tcp", target)
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return nil // ignore i/o timeout
		}
		return err
	}
	defer rConn.Close()
	if passage.Out != nil {
		switch passage.Out.Protocol {
		case model.ProtocolShadowsocks:
			rConn, err = NewTCPConn(rConn, CiphersConf[passage.Out.Method], passage.outMasterKey, nil)
			if err != nil {
				return err
			}
			defer rConn.Close()
			addr := targetMetadata.BytesFromPool()
			defer pool.Put(addr)
			if _, err = rConn.Write(addr); err != nil {
				return err
			}
		}
	}
	if err = server.RelayTCP(lConn, rConn); err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return nil // ignore i/o timeout
		}
		return fmt.Errorf("handleConn relay error: %w", err)
	}
	return nil
}

func (s *Server) authTCP(conn bufferred_conn.BufferedConn) (passage *Passage, err error) {
	var buf = pool.Get(BasicLen)
	defer pool.Put(buf)
	data, err := conn.Peek(BasicLen)
	if err != nil {
		return nil, io.ErrUnexpectedEOF
	}
	// find passage
	ctx := s.GetUserContextOrInsert(conn.RemoteAddr().(*net.TCPAddr).IP.String())
	passage, _ = ctx.Auth(func(passage Passage) ([]byte, bool) {
		return s.probeTCP(buf, data, passage)
	})
	if passage == nil {
		return nil, server.ErrFailAuth
	}
	// check bloom
	if exist := s.bloom.Exist(data[:CiphersConf[passage.In.Method].SaltLen]); exist {
		return nil, server.ErrReplayAttack
	}
	return passage, nil
}

func (s *Server) probeTCP(buf []byte, data []byte, passage Passage) ([]byte, bool) {
	//[salt][encrypted payload length][length tag][encrypted payload][payload tag]
	conf := CiphersConf[passage.In.Method]

	salt := data[:conf.SaltLen]
	cipherText := data[conf.SaltLen : conf.SaltLen+2+conf.TagLen]

	return conf.Verify(buf, passage.inMasterKey, salt, cipherText, nil)
}
