package shadowsocks

import (
	"context"
	"errors"
	"fmt"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/api"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/common"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/config"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/infra/ip_mtu_trie"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/infra/lru"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/log"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pool"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/SweetLisa/model"
	gonanoid "github.com/matoous/go-nanoid"
	disk_bloom "github.com/mzz2017/disk-bloom"
	"net"
	"strconv"
	"sync"
	"time"
)

func init() {
	server.Register("shadowsocks", New)
}

type Server struct {
	closed    chan struct{}
	sweetLisa *config.Lisa
	typ       string
	arg       server.Argument
	lastAlive time.Time
	// mutex protects passages
	mutex           sync.Mutex
	passages        []Passage
	userContextPool *UserContextPool
	listener        net.Listener
	udpConn         *net.UDPConn
	nm              *UDPConnMapping
	// passageContentionCache log the last client IP of passages
	passageContentionCache *server.ContentionCache

	bloom *disk_bloom.FilterGroup
}

type Passage struct {
	server.Passage
	inMasterKey  []byte
	outMasterKey []byte
}

func (p *Passage) Use() (use server.PassageUse) {
	if p.Manager {
		return server.PassageUseManager
	} else if p.In.From == "" {
		return server.PassageUseUser
	} else {
		return server.PassageUseRelay
	}
}

func New(valueCtx context.Context, sweetLisaHost *config.Lisa, arg server.Argument) (server.Server, error) {
	bloom := valueCtx.Value("bloom").(*disk_bloom.FilterGroup)
	s := &Server{
		userContextPool:        (*UserContextPool)(lru.New(lru.FixedTimeout, int64(1*time.Hour))),
		nm:                     NewUDPConnMapping(),
		sweetLisa:              sweetLisaHost,
		closed:                 make(chan struct{}),
		arg:                    arg,
		passageContentionCache: server.NewContentionCache(),
		bloom:                  bloom,
	}
	if sweetLisaHost != nil {
		if err := s.AddPassages([]server.Passage{{Manager: true}}); err != nil {
			return nil, err
		}

		// connect to SweetLisa and register
		if err := s.register(); err != nil {
			return nil, err
		}
		go s.registerBackground()
	}
	return s, nil
}

func (s *Server) registerBackground() {
	var interval = 2 * time.Second
	ticker := time.NewTicker(interval)
	for {
		select {
		case <-s.closed:
			ticker.Stop()
			break
		case <-ticker.C:
			if time.Since(s.lastAlive) < server.LostThreshold {
				continue
			} else {
				log.Warn("Lost connection with SweetLisa more than 5 minutes. Try to register again")
			}
			if err := s.register(); err != nil {
				// binary exponential backoff algorithm
				// to avoid DDoS
				interval = interval * 2
				if interval > 600*time.Second {
					interval = 600 * time.Second
				}
				log.Warn("registerBackground: %v. retry in %v", err, interval.String())
			} else {
				interval = 2 * time.Second
			}
			ticker.Reset(interval)
		}
	}
}

func (s *Server) register() error {
	var manager server.Passage
	users := s.Passages()
	for _, u := range users {
		if u.Manager {
			manager = u
			break
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	t, _ := net.LookupTXT("cdn-validate." + s.sweetLisa.Host)
	var validateToken string
	if len(t) > 0 {
		validateToken = t[0]
	}
	bandwidthLimit, err := server.GenerateBandwidthLimit()
	if err != nil {
		return err
	}
	cdnNames, users, err := api.Register(ctx, s.sweetLisa.Host, validateToken, model.Server{
		Ticket: s.arg.Ticket,
		Name:   s.arg.Name,
		Hosts:  s.arg.Hostnames,
		Port:   s.arg.Port,
		Argument: model.Argument{
			Protocol: model.ProtocolShadowsocks,
			Password: manager.In.Password,
			Method:   manager.In.Method,
		},
		BandwidthLimit: bandwidthLimit,
		NoRelay:        s.arg.NoRelay,
	})
	if err != nil {
		return err
	}
	log.Alert("Succeed to register at %v (%v)", strconv.Quote(s.sweetLisa.Host), cdnNames)
	s.lastAlive = time.Now()
	// sweetLisa can replace the manager key here
	if err := s.SyncPassages(users); err != nil {
		return err
	}
	return nil
}

func (s *Server) SyncPassages(passages []server.Passage) (err error) {
	return server.SyncPassages(s, passages)
}

func (s *Server) ListenTCP(addr string) (err error) {
	lt, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.listener = lt
	for {
		conn, err := lt.Accept()
		if err != nil {
			log.Warn("%v", err)
		}
		go func() {
			err := s.handleTCP(conn)
			if err != nil {
				if errors.Is(err, server.ErrPassageAbuse) ||
					errors.Is(err, server.ErrReplayAttack) {
					log.Warn("handleTCP: %v", err)
				} else {
					log.Info("handleTCP: %v", err)
				}
			}
		}()
	}
}

func (s *Server) ListenUDP(addr string) (err error) {
	_, strPort, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(strPort)
	if err != nil {
		return err
	}

	lu, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
	if err != nil {
		return err
	}
	s.udpConn = lu
	var buf [ip_mtu_trie.MTU]byte
	for {
		n, lAddr, err := lu.ReadFrom(buf[:])
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			log.Warn("ReadFrom: %v", err)
			continue
		}
		data := pool.Get(n)
		copy(data, buf[:n])
		go func() {
			err := s.handleUDP(lAddr, data)
			if err != nil {
				log.Warn("handleUDP: %v", err)
			}
			pool.Put(data)
		}()
	}
}

func (s *Server) Listen(addr string) (err error) {
	eCh := make(chan error, 2)
	go func() {
		e := s.ListenUDP(addr)
		eCh <- e
	}()
	go func() {
		e := s.ListenTCP(addr)
		eCh <- e
	}()
	defer s.Close()
	return <-eCh
}

func (s *Server) Close() error {
	close(s.closed)
	var err error
	if s.listener != nil {
		err = s.listener.Close()
	}
	if s.udpConn != nil {
		err2 := s.udpConn.Close()
		if err == nil {
			err = err2
		}
	}
	return err
}

func LocalizePassages(passages []server.Passage) (psgs []Passage, manager *Passage) {
	psgs = make([]Passage, len(passages))
	for i, psg := range passages {
		if psg.Manager {
			psg.In.Password, _ = gonanoid.Generate(common.Alphabet, 21)
			psg.In.Method = "aes-256-gcm"
			// allow only one manager
			if manager == nil {
				manager = &psgs[i]
			} else {
				psg.Manager = false
				log.Warn("found more than one manager")
			}
		}
		psgs[i].Passage = psg
		if psgs[i].In.Method == "" {
			psgs[i].In.Method = "chacha20-ietf-poly1305"
		}
		psgs[i].inMasterKey = EVPBytesToKey(psg.In.Password, CiphersConf[psg.In.Method].KeyLen)
		// TODO: other protocols
		if psg.Out != nil && psg.Out.Protocol == model.ProtocolShadowsocks {
			psgs[i].outMasterKey = EVPBytesToKey(psg.Out.Password, CiphersConf[psg.Out.Method].KeyLen)
		}
	}
	return psgs, manager
}

func (s *Server) AddPassages(passages []server.Passage) (err error) {
	log.Trace("AddPassages: %v", len(passages))
	us, managerKey := LocalizePassages(passages)
	s.mutex.Lock()
	defer s.mutex.Unlock()
	// update manager key
	if managerKey != nil {
		// remove manager key in UserContext
		s.removePassagesFunc(func(passage Passage) (remove bool) {
			return passage.Manager == true
		})
	}
	s.addPassages(us)
	return nil
}

func (s *Server) RemovePassages(passages []server.Passage, alsoManager bool) (err error) {
	log.Trace("RemovePassages: %v, alsoManager: %v", len(passages), alsoManager)
	psgs, _ := LocalizePassages(passages)
	s.mutex.Lock()
	defer s.mutex.Unlock()
	var keySet = make(map[string]struct{})
	for _, passage := range psgs {
		if passage.Manager && !alsoManager {
			continue
		}
		keySet[passage.In.Argument.Hash()] = struct{}{}
	}
	s.removePassagesFunc(func(passage Passage) (remove bool) {
		_, ok := keySet[passage.In.Argument.Hash()]
		return ok
	})
	return nil
}

func (s *Server) Passages() (passages []server.Passage) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	for _, passage := range s.passages {
		passages = append(passages, passage.Passage)
	}
	return passages
}

func (s *Server) addPassages(passages []Passage) {
	s.passages = append(s.passages, passages...)

	var vals []interface{}
	for _, k := range passages {
		vals = append(vals, k)
	}
	socketIdents := s.userContextPool.Infra().GetKeys()
	for _, ident := range socketIdents {
		userContext := s.userContextPool.Infra().Get(ident).(*UserContext).Infra()
		userContext.Insert(vals)
	}
}

func (s *Server) removePassagesFunc(f func(passage Passage) (remove bool)) {
	for i := len(s.passages) - 1; i >= 0; i-- {
		if f(s.passages[i]) {
			s.passages = append(s.passages[:i], s.passages[i+1:]...)
		}
	}
	socketIdents := s.userContextPool.Infra().GetKeys()
	for _, ident := range socketIdents {
		userContext := s.userContextPool.Infra().Get(ident).(*UserContext).Infra()
		listCopy := userContext.GetListCopy()
		for _, node := range listCopy {
			if f(node.Val.(Passage)) {
				userContext.Remove(node)
			}
		}
		userContext.DestroyListCopy(listCopy)
	}
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
