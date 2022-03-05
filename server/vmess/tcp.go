package vmess

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/config"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/log"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pool"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/protocol"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/protocol/vmess"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/SweetLisa/model"
	jsoniter "github.com/json-iterator/go"
	"io"
	"net"
	"strconv"
	"time"
)

func (s *Server) handleConn(conn net.Conn) error {
	defer conn.Close()
	passage, eAuthID, err := s.authFromPool(conn)
	if err != nil {
		// Auth fail. Drain the conn
		if config.ParamsObj.John.MaxDrainN == -1 {
			io.Copy(io.Discard, conn)
		} else {
			io.CopyN(io.Discard, conn, config.ParamsObj.John.MaxDrainN)
		}
		return fmt.Errorf("auth fail: %w. Drained the conn from: %v", err, conn.RemoteAddr().String())
	}

	// detect passage contention
	if err := s.ContentionCheck(conn.RemoteAddr().(*net.TCPAddr).IP, passage); err != nil {
		if config.ParamsObj.John.MaxDrainN == -1 {
			io.Copy(io.Discard, conn)
		} else {
			io.CopyN(io.Discard, conn, config.ParamsObj.John.MaxDrainN)
		}
		return err
	}
	metadata := vmess.NewServerMetadata(passage.inCmdKey, eAuthID)
	pool.Put(eAuthID)
	// handle connection
	var target string
	lConn, err := vmess.NewConn(conn, *metadata, passage.inCmdKey)
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
	if targetMetadata.Type == protocol.MetadataTypeMsg {
		return s.handleMsg(lConn, &targetMetadata, passage)
	}
	target = net.JoinHostPort(targetMetadata.Hostname, strconv.Itoa(int(targetMetadata.Port)))

	// manager should not come to this line
	if passage.Manager {
		return fmt.Errorf("%w: manager key is ubused for a non-cmd connection", server.ErrPassageAbuse)
	}

	// Dial and relay
	dialer := s.dialer
	if passage.Out != nil {
		dialer, err = protocol.NewDialer(string(passage.Out.Protocol), dialer, protocol.Header{
			ProxyAddress: net.JoinHostPort(passage.Out.Host, passage.Out.Port),
			Cipher:       passage.Out.Method,
			Password:     passage.Out.Password,
			IsClient:     true,
		})
		if err != nil {
			return err
		}
	}
	switch targetMetadata.Network {
	case "tcp":
		rConn, err := dialer.Dial("tcp", target)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				log.Debug("%v", err)
				return nil // ignore i/o timeout
			}
			return err
		}
		defer rConn.Close()
		if err = server.RelayTCP(lConn, rConn); err != nil {
			var netErr net.Error
			if errors.Is(err, io.EOF) || (errors.As(err, &netErr) && netErr.Timeout()) {
				return nil // ignore i/o timeout
			}
			return fmt.Errorf("relay error: %w", err)
		}
	case "udp":
		udpAddr, err := net.ResolveUDPAddr("udp", target)
		if err != nil {
			return err
		}
		rConn, err := dialer.Dial("udp", udpAddr.String())
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				return nil // ignore i/o timeout
			}
			return err
		}
		//log.Trace("rConn.RemoteAddr(): %v", rConn.RemoteAddr())
		if err = relayUoT(rConn.(net.PacketConn), udpAddr, lConn); err != nil {
			var netErr net.Error
			if errors.Is(err, io.EOF) || (errors.As(err, &netErr) && netErr.Timeout()) {
				return nil // ignore i/o timeout
			}
			return fmt.Errorf("relay error: %w", err)
		}
	default:
		return fmt.Errorf("unexpected instruction cmd: %v", targetMetadata.Network)
	}
	return nil
}

func (s *Server) authFromPool(conn net.Conn) (passage *Passage, eAuthID []byte, err error) {
	eAuthID = pool.Get(16)
	_, err = io.ReadFull(conn, eAuthID)
	if err != nil {
		pool.Put(eAuthID)
		return nil, nil, err
	}
	userContext := s.GetUserContextOrInsert(conn.RemoteAddr().(*net.TCPAddr).IP.String())
	hit, _ := userContext.Auth(func(passage *Passage) ([]byte, bool) {
		if err = vmess.AuthEAuthID(passage.inEAuthIDBlock, eAuthID, s.doubleCuckoo, s.startTimestamp); err == nil {
			return nil, true
		}
		return nil, false
	})
	if errors.Is(err, protocol.ErrReplayAttack) || errors.Is(err, protocol.ErrFailAuth) {
		pool.Put(eAuthID)
		return nil, nil, err
	}
	if hit == nil {
		pool.Put(eAuthID)
		return nil, nil, fmt.Errorf("%w: not found", protocol.ErrFailAuth)
	}
	return hit, eAuthID, nil
}

func (s *Server) handleMsg(conn *vmess.Conn, reqMetadata *vmess.Metadata, passage *Passage) error {
	if !passage.Manager {
		return fmt.Errorf("handleMsg: illegal message received from a non-manager passage")
	}
	if reqMetadata.Type != protocol.MetadataTypeMsg {
		return fmt.Errorf("handleMsg: this connection is not for message")
	}
	log.Trace("handleMsg(vmess): cmd: %v", reqMetadata.Cmd)

	// we know the body length but we should read all
	bufLen := pool.Get(4)
	defer pool.Put(bufLen)
	if _, err := io.ReadFull(conn, bufLen); err != nil {
		return err
	}

	var reqBody = io.LimitReader(conn, int64(binary.BigEndian.Uint32(bufLen)))

	var resp []byte
	switch reqMetadata.Cmd {
	case protocol.MetadataCmdPing:
		buf := pool.Get(4)
		defer pool.Put(buf)
		if _, err := io.ReadFull(reqBody, buf); err != nil {
			return err
		}
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
	case protocol.MetadataCmdSyncPassages:
		var passages []model.Passage
		if err := jsoniter.NewDecoder(reqBody).Decode(&passages); err != nil {
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
		return fmt.Errorf("%w: unexpected metadata cmd type: %v", protocol.ErrFailAuth, reqMetadata.Cmd)
	}
	buf := pool.Get(len(resp) + 4)
	defer pool.Put(buf)
	binary.BigEndian.PutUint32(buf, uint32(len(resp)))
	copy(buf[4:], resp)
	_, err := conn.Write(buf)
	return err
}

func relayConnToUDP(dst net.PacketConn, raddr *net.UDPAddr, src *vmess.Conn, timeout time.Duration) (err error) {
	var n int
	buf := pool.Get(vmess.MaxUDPSize)
	defer pool.Put(buf)
	for {
		_ = src.SetReadDeadline(time.Now().Add(timeout))
		n, err = src.Read(buf)
		if err != nil {
			return
		}
		_ = dst.SetWriteDeadline(time.Now().Add(server.DefaultNatTimeout)) // should keep consistent
		_, err = dst.WriteTo(buf[:n], raddr)
		// WARNING: if the dst is an pre-connected conn, Write should be invoked here.
		if errors.Is(err, net.ErrWriteToConnected) {
			log.Error("relayConnToUDP: %v", err)
		}
		if err != nil {
			return
		}
	}
}

func relayUoT(rConn net.PacketConn, raddr *net.UDPAddr, lConn *vmess.Conn) (err error) {
	eCh := make(chan error, 1)
	go func() {
		e := relayConnToUDP(rConn, raddr, lConn, server.DefaultNatTimeout)
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
