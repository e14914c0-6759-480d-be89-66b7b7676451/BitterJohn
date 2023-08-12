package juicity

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/log"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/SweetLisa/model"
	jsoniter "github.com/json-iterator/go"

	"github.com/daeuniverse/softwind/netproxy"
	"github.com/daeuniverse/softwind/pool"
	"github.com/daeuniverse/softwind/protocol"
	"github.com/daeuniverse/softwind/protocol/direct"
	"github.com/daeuniverse/softwind/protocol/juicity"
	"github.com/daeuniverse/softwind/protocol/trojanc"
	"github.com/daeuniverse/softwind/protocol/tuic"
	"github.com/daeuniverse/softwind/protocol/tuic/common"
	"github.com/google/uuid"
	"github.com/mzz2017/quic-go"
)

const (
	AuthenticateTimeout = 10 * time.Second
	AcceptTimeout       = AuthenticateTimeout
)

var (
	ErrUnexpectedVersion    = fmt.Errorf("unexpected version")
	ErrUnexpectedCmdType    = fmt.Errorf("unexpected cmd type")
	ErrAuthenticationFailed = fmt.Errorf("authentication failed")
)

type Options struct {
	Certificate       []byte
	PrivateKey        []byte
	CongestionControl string
	SendThrough       string
}

func New(opts *Options) (*Server, error) {
	cert, err := tls.X509KeyPair(opts.Certificate, opts.PrivateKey)
	if err != nil {
		return nil, err
	}
	dialer := direct.FullconeDirect
	if opts.SendThrough != "" {
		lAddr, err := netip.ParseAddr(opts.SendThrough)
		if err != nil {
			return nil, fmt.Errorf("parse send_through: %w", err)
		}
		dialer = direct.NewDirectDialerLaddr(true, lAddr)
	}
	return &Server{
		dialer: dialer,
		tlsConfig: &tls.Config{
			NextProtos:   []string{"h3"}, // h3 only.
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{cert},
		},
		maxOpenIncomingStreams: 100,
		congestionControl:      opts.CongestionControl,
		cwnd:                   10,
	}, nil
}

func (s *Server) Serve(addr string) (err error) {
	quicMaxOpenIncomingStreams := int64(s.maxOpenIncomingStreams)

	listener, err := quic.ListenAddr(addr, s.tlsConfig, &quic.Config{
		MaxIncomingStreams:      quicMaxOpenIncomingStreams,
		MaxIncomingUniStreams:   quicMaxOpenIncomingStreams,
		KeepAlivePeriod:         10 * time.Second,
		DisablePathMTUDiscovery: false,
		EnableDatagrams:         false,
		CapabilityCallback:      nil,
	})
	if err != nil {
		return err
	}
	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			return err
		}
		go func(conn quic.Connection) {
			if err := s.handleConn(conn); err != nil {
				var netError net.Error
				if errors.As(err, &netError) && netError.Timeout() {
					return // ignore i/o timeout
				}
				log.Warn("%v", err)
			}
		}(conn)
	}
}

func (s *Server) handleConn(conn quic.Connection) (err error) {
	common.SetCongestionController(conn, s.congestionControl, s.cwnd)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	authCtx, authDone := context.WithCancel(ctx)
	defer authDone()
	var id uuid.UUID
	go func() {
		if _id, err := s.handleAuth(ctx, conn); err != nil {
			log.Warn("handleAuth: %v", err)
			cancel()
			_ = conn.CloseWithError(tuic.AuthenticationFailed, "")
		} else {
			id = *_id
			authDone()
		}
	}()
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return err
		}
		go func(stream quic.Stream) {
			if err = s.handleStream(ctx, authCtx, &id, conn, stream); err != nil {
				log.Warn("handleStream: %v", err)
			}
		}(stream)
	}
}

func (s *Server) handleStream(ctx context.Context, authCtx context.Context, id *uuid.UUID, conn quic.Connection, stream quic.Stream) error {
	defer stream.Close()
	lConn := juicity.NewConn(stream, nil, nil)
	// Read the header and initiate the metadata
	_, err := lConn.Read(nil)
	if err != nil {
		return err
	}
	<-authCtx.Done()
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	// detect passage contention
	_passage, ok := s.users.Load(*id)
	if !ok {
		return fmt.Errorf("no such user: %v", *id)
	}
	passage := _passage.(*Passage)
	if err := s.ContentionCheck(conn.RemoteAddr().(*net.UDPAddr).IP, passage); err != nil {
		return err
	}
	mdata := lConn.Metadata
	if mdata.Type == protocol.MetadataTypeMsg {
		return s.handleMsg(lConn, mdata, passage)
	}
	// manager should not come to this line
	if passage.Manager {
		return fmt.Errorf("%w: manager key is ubused for a non-cmd connection", server.ErrPassageAbuse)
	}
	dialer := s.dialer
	if passage.Out != nil {
		header, err := server.GetHeader(*passage.Out, &s.sweetLisa)
		if err != nil {
			return err
		}
		dialer, err = server.NewDialer(string(passage.Out.Protocol), dialer, header)
		if err != nil {
			return err
		}
	}
	target := net.JoinHostPort(mdata.Hostname, strconv.Itoa(int(mdata.Port)))
	d := &netproxy.ContextDialerConverter{
		Dialer: dialer,
	}
	ctx, cancel := context.WithTimeout(ctx, server.DialTimeout)
	defer cancel()
	switch mdata.Network {
	case "tcp":
		rConn, err := d.DialContext(ctx, "tcp", target)
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
			if errors.Is(err, io.EOF) || (errors.As(err, &netErr) && netErr.Timeout()) || strings.HasSuffix(err.Error(), "with error code 0") {
				return nil // ignore i/o timeout
			}
			return fmt.Errorf("relay tcp error: %w", err)
		}
	case "udp":
		// can dial any target
		lConn := &juicity.PacketConn{Conn: lConn}
		buf := pool.GetFullCap(1500)
		defer pool.Put(buf)
		_ = lConn.SetReadDeadline(time.Now().Add(server.DefaultNatTimeout))
		n, addr, err := lConn.ReadFrom(buf)
		if err != nil {
			return fmt.Errorf("ReadFrom: %w", err)
		}

		c, err := d.DialContext(ctx, "udp", addr.String())
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				return nil // ignore i/o timeout
			}
			return fmt.Errorf("Dial: %w", err)
		}
		rConn := c.(netproxy.PacketConn)
		_ = rConn.SetWriteDeadline(time.Now().Add(server.DefaultNatTimeout)) // should keep consistent
		_, err = rConn.WriteTo(buf[:n], addr.String())
		if err != nil {
			if errors.Is(err, net.ErrWriteToConnected) {
				log.Warn("relayConnToUDP: %v", err)
			}
			return fmt.Errorf("WriteTo: %w", err)
		}
		if err = relayUoT(
			rConn,
			lConn,
			len(buf),
		); err != nil {
			var netErr net.Error
			if errors.Is(err, io.EOF) || (errors.As(err, &netErr) && netErr.Timeout()) || strings.HasSuffix(err.Error(), "with error code 0") {
				return nil // ignore i/o timeout
			}
			return fmt.Errorf("relay udp error: %w", err)
		}
	default:
		return fmt.Errorf("unexpected network: %v", mdata.Network)
	}
	return nil
}

func (s *Server) handleAuth(ctx context.Context, conn quic.Connection) (uuid *uuid.UUID, err error) {
	ctx, cancel := context.WithTimeout(ctx, AuthenticateTimeout)
	defer cancel()
	uniStream, err := conn.AcceptUniStream(ctx)
	if err != nil {
		return nil, err
	}
	r := bufio.NewReader(uniStream)
	v, err := r.Peek(1)
	if err != nil {
		return nil, err
	}
	switch v[0] {
	case juicity.Version0:
		commandHead, err := tuic.ReadCommandHead(r)
		if err != nil {
			return nil, fmt.Errorf("ReadCommandHead: %w", err)
		}
		switch commandHead.TYPE {
		case tuic.AuthenticateType:
			authenticate, err := tuic.ReadAuthenticateWithHead(commandHead, r)
			if err != nil {
				return nil, fmt.Errorf("ReadAuthenticateWithHead: %w", err)
			}
			var token [32]byte
			if passage, ok := s.users.Load(authenticate.UUID); ok {
				token, err = tuic.GenToken(conn.ConnectionState(), authenticate.UUID, passage.(*Passage).In.Password)
				if err != nil {
					return nil, fmt.Errorf("GenToken: %w", err)
				}
				if token == authenticate.TOKEN {
					return &authenticate.UUID, nil
				} else {
					_ = conn.CloseWithError(tuic.AuthenticationFailed, ErrAuthenticationFailed.Error())
				}
			}
			return nil, fmt.Errorf("%w: %v", ErrAuthenticationFailed, authenticate.UUID)
		default:
			return nil, fmt.Errorf("%w: %v", ErrUnexpectedCmdType, commandHead.TYPE)
		}
	default:
		return nil, fmt.Errorf("%w: %v", ErrUnexpectedVersion, v)
	}
}

func (s *Server) handleMsg(conn *juicity.Conn, reqMetadata *trojanc.Metadata, passage *Passage) error {
	if !passage.Manager {
		return fmt.Errorf("handleMsg: illegal message received from a non-manager passage")
	}
	if reqMetadata.Type != protocol.MetadataTypeMsg {
		return fmt.Errorf("handleMsg: this connection is not for message")
	}
	log.Trace("handleMsg(juicity): cmd: %v", reqMetadata.Cmd)

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
