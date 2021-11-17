package vmess

import (
	"context"
	"crypto/aes"
	"errors"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/api"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/config"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/log"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/protocol/vmess"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/SweetLisa/model"
	"github.com/google/uuid"
	"golang.org/x/net/proxy"
	"net"
	"strconv"
	"sync"
	"time"
)

func init() {
	server.Register("vmess", NewJohn)
}

type Server struct {
	closed    chan struct{}
	sweetLisa config.Lisa
	arg       server.Argument
	lastAlive time.Time

	listener net.Listener
	mutex    sync.Mutex
	passages []Passage
	// passageContentionCache log the last client IP of passages
	passageContentionCache *server.ContentionCache

	startTimestamp int64

	doubleCuckoo *vmess.ReplayFilter
	dialer       proxy.Dialer
}

func New(valueCtx context.Context, dialer proxy.Dialer) (server.Server, error) {
	doubleCuckoo := valueCtx.Value("doubleCuckoo").(*vmess.ReplayFilter)
	s := &Server{
		doubleCuckoo: doubleCuckoo,
		dialer:       dialer,
		closed:       make(chan struct{}),
	}
	return s, nil
}

func NewJohn(valueCtx context.Context, dialer proxy.Dialer, sweetLisaHost config.Lisa, arg server.Argument) (server.Server, error) {
	s, err := New(valueCtx, dialer)
	if err != nil {
		return nil, err
	}
	john := s.(*Server)
	john.sweetLisa = sweetLisaHost
	john.arg = arg
	john.passageContentionCache = server.NewContentionCache()
	if err := s.AddPassages([]server.Passage{{Manager: true}}); err != nil {
		return nil, err
	}

	// connect to SweetLisa and register
	if err := john.register(); err != nil {
		return nil, err
	}
	go john.registerBackground()
	return john, nil
}

func (s *Server) Listen(addr string) (err error) {
	lt, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.startTimestamp = time.Now().Unix()
	s.listener = lt
	for {
		conn, err := lt.Accept()
		if err != nil {
			log.Warn("%v", err)
		}
		go func() {
			err := s.handleConn(conn)
			if err != nil {
				if errors.Is(err, server.ErrPassageAbuse) ||
					errors.Is(err, server.ErrReplayAttack) {
					log.Warn("handleConn: %v", err)
				} else {
					log.Info("handleConn: %v", err)
				}
			}
		}()
	}
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

func LocalizePassages(passages []server.Passage) (psgs []Passage, manager *Passage) {
	psgs = make([]Passage, len(passages))
	for i, psg := range passages {
		if psg.Manager {
			psg.In.Password = uuid.New().String()
			// allow only one manager
			if manager == nil {
				manager = &psgs[i]
			} else {
				psg.Manager = false
				log.Warn("found more than one manager")
			}
		}
		psgs[i].Passage = psg
		id, err := uuid.Parse(psgs[i].In.Password)
		if err != nil {
			log.Warn("LocalizePassages: invalid uuid: %v", psgs[i].In.Password)
			id = uuid.New()
		}
		psgs[i].inCmdKey = vmess.NewID(id).CmdKey()
		psgs[i].inEAuthIDBlock, _ = aes.NewCipher(vmess.KDF(psgs[i].inCmdKey, []byte(vmess.KDFSaltConstAuthIDEncryptionKey))[:16])
		if psg.Out != nil && psg.Out.Protocol == model.ProtocolVMessTCP {
			id, err := uuid.Parse(psgs[i].Out.Password)
			if err != nil {
				log.Warn("LocalizePassages: invalid uuid: %v", psgs[i].In.Password)
				id = uuid.New()
			}
			psgs[i].outCmdKey = vmess.NewID(id).CmdKey()
		}
	}
	return psgs, manager
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

func (s *Server) SyncPassages(passages []server.Passage) (err error) {
	return server.SyncPassages(s, passages)
}

func (s *Server) Passages() (passages []server.Passage) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	for _, passage := range s.passages {
		passages = append(passages, passage.Passage)
	}
	return passages
}

func (s *Server) Close() error {
	return s.listener.Close()
}

func (s *Server) addPassages(passages []Passage) {
	s.passages = append(s.passages, passages...)
}

func (s *Server) removePassagesFunc(f func(passage Passage) (remove bool)) {
	for i := len(s.passages) - 1; i >= 0; i-- {
		if f(s.passages[i]) {
			s.passages = append(s.passages[:i], s.passages[i+1:]...)
		}
	}
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
			Protocol: model.ProtocolVMessTCP,
			Password: manager.In.Password,
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
