package juicity

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/daeuniverse/softwind/netproxy"
	"github.com/daeuniverse/softwind/protocol"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/api"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/common"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/config"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/log"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/SweetLisa/model"
	"github.com/google/uuid"
	gonanoid "github.com/matoous/go-nanoid"
)

func init() {
	server.Register("juicity", NewJohn)
}

const (
	ManagerUuid = "00000000-0000-0000-0000-000000000000"
	Domain      = "software.download.prss.microsoft.com"
)

type Server struct {
	dialer                 netproxy.Dialer
	tlsConfig              *tls.Config
	maxOpenIncomingStreams int64
	congestionControl      string
	cwnd                   int
	users                  sync.Map

	sweetLisa             config.Lisa
	arg                   server.Argument
	pinnedCertchainSha256 string
	// mutex protects passages
	mutex    sync.Mutex
	passages []Passage
	// passageContentionCache log the last client IP of passages
	passageContentionCache *server.ContentionCache
	lastAlive              time.Time
	ctx                    context.Context
	close                  func()
	listener               net.Listener
}

type Passage struct {
	server.Passage
	uuid uuid.UUID
}

func NewJohn(valueCtx context.Context, dialer netproxy.Dialer, sweetLisa config.Lisa, arg server.Argument) (server.Server, error) {
	cert := valueCtx.Value("certificate").([]byte)
	key := valueCtx.Value("key").([]byte)
	s, err := New(&Options{
		Certificate:       cert,
		PrivateKey:        key,
		CongestionControl: "bbr",
		SendThrough:       "",
	})
	if err != nil {
		return nil, err
	}
	john := s
	john.sweetLisa = sweetLisa
	john.arg = arg
	john.pinnedCertchainSha256, err = common.GenerateCertChainHashFromBytes(cert)
	if err != nil {
		return nil, err
	}
	john.passageContentionCache = server.NewContentionCache()
	if err := s.AddPassages([]server.Passage{{Manager: true}}); err != nil {
		return nil, err
	}
	john.ctx, john.close = context.WithCancel(context.Background())

	// connect to SweetLisa and register
	if err := john.register(); err != nil {
		return nil, err
	}
	go john.registerBackground()
	return john, nil
}

func (s *Server) registerBackground() {
	var interval = 2 * time.Second
	ticker := time.NewTicker(interval)
	for {
		select {
		case <-s.ctx.Done():
			ticker.Stop()
			log.Debug("Server was closed")
			return
		case <-ticker.C:
			if time.Since(s.lastAlive) < server.LostThreshold {
				continue
			} else {
				log.Warn("Lost connection with SweetLisa more than 5 minutes. Try to register again")
			}
			if err := s.register(); err != nil {
				// binary exponential backoff algorithm
				// to avoid DDoS
				interval *= 2
				if interval > 600*time.Second {
					interval = 600 * time.Second
				}
				log.Warn("registerBackground: %v. retry in %v", err, interval.String())
			} else {
				log.Debug("Suc Reg")
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
		Name:   s.arg.ServerName,
		Hosts:  s.arg.Hostnames,
		Port:   s.arg.Port,
		Argument: model.Argument{
			Protocol: protocol.ProtocolJuicity,
			Username: manager.In.Username,
			Password: manager.In.Password,
			Method:   "pinned_certchain_sha256=" + s.pinnedCertchainSha256,
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

func (s *Server) Listen(addr string) (err error) {
	return s.Serve(addr)
}

func (s *Server) Close() error {
	s.close()
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func LocalizePassages(passages []server.Passage) (psgs []Passage, manager *Passage) {
	psgs = make([]Passage, len(passages))
	for i, psg := range passages {
		if psg.Manager {
			psg.In.Username = ManagerUuid
			psg.In.Password, _ = gonanoid.Generate(common.Alphabet, 23)
			// allow only one manager
			if manager == nil {
				manager = &psgs[i]
			} else {
				psg.Manager = false
				log.Warn("found more than one manager")
			}
		}
		psgs[i].Passage = psg
		psgs[i].uuid, _ = uuid.Parse(psg.In.Username)
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
		s.removePassagesFunc(func(passage *Passage) (remove bool) {
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
	s.removePassagesFunc(func(passage *Passage) (remove bool) {
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

	for i := range passages {
		s.users.Store(s.passages[i].uuid, &s.passages[i])
	}
}

func (s *Server) removePassagesFunc(f func(passage *Passage) (remove bool)) {
	for i := len(s.passages) - 1; i >= 0; i-- {
		if f(&s.passages[i]) {
			s.users.Delete(s.passages[i].uuid)
			s.passages = append(s.passages[:i], s.passages[i+1:]...)
		}
	}
}

func (s *Server) ContentionCheck(thisIP net.IP, passage *Passage) (err error) {
	if s.passageContentionCache == nil {
		return nil
	}
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
