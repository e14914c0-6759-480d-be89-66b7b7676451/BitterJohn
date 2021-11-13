package vmess

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
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
	TCPBufferSize = 32 * 1024
)

func (s *Server) handleConn(conn net.Conn) error {
	defer conn.Close()
	passage, eAuthID, err := s.authFromPool(conn)
	if err != nil {
		// Auth fail. Drain the conn
		io.Copy(io.Discard, conn)
		return fmt.Errorf("auth fail: %w. Drained the conn from: %v", err, conn.RemoteAddr().String())
	}

	// detect passage contention
	if err := s.ContentionCheck(conn.RemoteAddr().(*net.TCPAddr).IP, passage); err != nil {
		io.Copy(io.Discard, conn)
		return err
	}

	metadata := Metadata{IsClient: false}
	copy(metadata.authedCmdKey[:], passage.inCmdKey)
	copy(metadata.authedEAuthID[:], eAuthID)
	pool.Put(eAuthID)
	// handle connection
	var target string
	lConn, err := NewConn(conn, metadata, passage.inCmdKey)
	if err != nil {
		return err
	}
	defer lConn.Close()
	// Read the header and initiate the metadata
	_, err = lConn.Read(nil)
	if err != nil {
		return err
	}
	targetMetadata := lConn.Metadata()
	if targetMetadata.Type == MetadataTypeMsg {
		return s.handleMsg(lConn, &targetMetadata, passage)
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
	switch targetMetadata.InsCmd {
	case InstructionCmdTCP:
		rConn, err := server.DefaultLimitedDialer.Dial("tcp", target)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				log.Debug("%v", err)
				return nil // ignore i/o timeout
			}
			return err
		}
		defer rConn.Close()
		if passage.Out != nil {
			switch passage.Out.Protocol {
			case model.ProtocolVMessTCP:
				targetMetadata.Cipher = CipherAES128GCM
				targetMetadata.IsClient = true
				rConn, err = NewConn(rConn, targetMetadata, passage.outCmdKey)
				if err != nil {
					return err
				}
				defer rConn.Close()
			}
		}
		if err = server.RelayTCP(lConn, rConn); err != nil {
			var netErr net.Error
			if errors.Is(err, io.EOF) || (errors.As(err, &netErr) && netErr.Timeout()) {
				return nil // ignore i/o timeout
			}
			return fmt.Errorf("relay error: %w", err)
		}
	case InstructionCmdUDP:
		// udp
		// symmetric nat
		rConn, err := server.DefaultLimitedDialer.Dial("udp", target)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				return nil // ignore i/o timeout
			}
			return err
		}
		if err = relayUoT(rConn.(*net.UDPConn), rConn.RemoteAddr(), lConn); err != nil {
			var netErr net.Error
			if errors.Is(err, io.EOF) || (errors.As(err, &netErr) && netErr.Timeout()) {
				return nil // ignore i/o timeout
			}
			return fmt.Errorf("relay error: %w", err)
		}
	default:
		return fmt.Errorf("unexpected instruction cmd: %v", targetMetadata.InsCmd)
	}
	return nil
}

func (s *Server) authFromPool(conn net.Conn) (passage *Passage, eAuthID []byte, err error) {
	eAuthID = pool.Get(16)
	_, err = io.ReadFull(conn, eAuthID)
	if err != nil {
		return nil, nil, err
	}
	var passages = make([]Passage, len(s.passages))
	s.mutex.Lock()
	copy(passages, s.passages)
	s.mutex.Unlock()
	for i := range passages {
		if err := AuthEAuthID(passages[i].inEAuthIDBlock, eAuthID, s.doubleCuckoo, s.startTimestamp); errors.Is(err, server.ErrReplayAttack) || errors.Is(err, server.ErrFailAuth) {
			pool.Put(eAuthID)
			return nil, nil, err
		} else if err == nil {
			return &passages[i], eAuthID, nil
		}
	}
	pool.Put(eAuthID)
	return nil, nil, fmt.Errorf("%w: not found", server.ErrFailAuth)
}

func (s *Server) ContentionCheck(thisIP net.IP, passage *Passage) (err error) {
	contentionDuration := server.ProtectTime[passage.Use()]
	if contentionDuration > 0 {
		passageKey := passage.In.Argument.Hash()
		accept, conflictIP := s.passageContentionCache.Check(passageKey, contentionDuration, thisIP)
		if !accept {
			return fmt.Errorf("%w: from %v and %v: contention detected", server.ErrPassageAbuse, thisIP.String(), conflictIP.String())
		}
	}
	return nil
}

func (s *Server) handleMsg(conn *Conn, reqMetadata *Metadata, passage *Passage) error {
	if !passage.Manager {
		return fmt.Errorf("handleMsg: illegal message received from a non-manager passage")
	}
	if reqMetadata.Type != MetadataTypeMsg {
		return fmt.Errorf("handleMsg: this connection is not for message")
	}
	log.Trace("handleMsg: cmd: %v", reqMetadata.Cmd)

	// we know the body length but we should read all
	bufLen := pool.Get(4)
	defer pool.Put(bufLen)
	if _, err := io.ReadFull(conn, bufLen); err != nil {
		return err
	}
	buf := pool.Get(int(binary.BigEndian.Uint32(bufLen) & 0xfffff))
	defer pool.Put(buf)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}

	var resp []byte
	switch reqMetadata.Cmd {
	case server.MetadataCmdPing:
		if !bytes.Equal(buf, []byte("ping")) {
			log.Warn("the body of received ping message is %v instead of %v", strconv.Quote(string(buf)), strconv.Quote("ping"))
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
		resp = bPingResp
	case server.MetadataCmdSyncPassages:
		var passages []model.Passage
		if err := jsoniter.Unmarshal(buf, &passages); err != nil {
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

		resp = pool.Get(2)
		defer pool.Put(resp)
		copy(resp, "OK")
	default:
		return fmt.Errorf("%w: unexpected metadata cmd type: %v", server.ErrFailAuth, reqMetadata.Cmd)
	}
	buf = pool.Get(len(resp) + 4)
	defer pool.Put(buf)
	binary.BigEndian.PutUint32(buf, uint32(len(resp)))
	copy(buf[4:], resp)
	_, err := conn.Write(buf)
	return err
}

func relayConnToUDP(dst *net.UDPConn, src *Conn, timeout time.Duration) (err error) {
	var n int
	buf := pool.Get(MaxChunkSize)
	defer pool.Put(buf)
	for {
		_ = src.SetReadDeadline(time.Now().Add(timeout))
		n, err = src.Read(buf)
		if err != nil {
			return
		}
		_ = dst.SetWriteDeadline(time.Now().Add(server.DefaultNatTimeout)) // should keep consistent
		_, err = dst.Write(buf[:n])
		if err != nil {
			return
		}
	}
}

func relayUoT(rConn *net.UDPConn, raddr net.Addr, lConn *Conn) (err error) {
	eCh := make(chan error, 1)
	go func() {
		e := relayConnToUDP(rConn, lConn, server.DefaultNatTimeout)
		rConn.SetReadDeadline(time.Now().Add(10 * time.Second))
		eCh <- e
	}()
	e := server.RelayUDPToConn(lConn, rConn, server.DefaultNatTimeout)
	if lConn, ok := lConn.Conn.(server.WriteCloser); ok {
		lConn.CloseWrite()
	}
	lConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if e != nil {
		var netErr net.Error
		if errors.As(e, &netErr) && netErr.Timeout() {
			return <-eCh
		}
		<-eCh
		return e
	}
	return <-eCh
}
