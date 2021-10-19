package shadowsocks

import (
	"errors"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/common"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/infra/lru"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/api"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/log"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pool"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/SweetLisa/model"
	gonanoid "github.com/matoous/go-nanoid"
	"net"
	"strconv"
	"sync"
	"time"
)

func init() {
	server.Register("shadowsocks", New)
}

const (
	MTU = 65535
)

type Server struct {
	closed         chan struct{}
	sweetLisaHost  string
	chatIdentifier string
	typ            string
	arg            server.Argument
	lastAlive      time.Time
	// mutex protects keys
	mutex           sync.Mutex
	keys            []Key
	userContextPool *UserContextPool
	listener        net.Listener
	udpConn         *net.UDPConn
	nm              *UDPConnMapping
}

type Key struct {
	password  string
	method    string
	masterKey []byte
	manager   bool
	forwardTo string
}

func New(sweetLisaHost, chatIdentifier string, arg server.Argument) (server.Server, error) {
	s := Server{
		userContextPool: (*UserContextPool)(lru.New(lru.FixedTimeout, int64(1*time.Hour))),
		nm:              NewUDPConnMapping(),
		sweetLisaHost:   sweetLisaHost,
		chatIdentifier:  chatIdentifier,
		closed:          make(chan struct{}),
		arg:             arg,
	}
	if err := s.AddUsers([]server.User{{Manager: true}}); err != nil {
		return nil, err
	}

	// connect to SweetLisa and register
	if err := s.register(); err != nil {
		return nil, err
	}
	go s.registerBackground()
	return &s, nil
}

func (s *Server) registerBackground() {
	const interval = 10 * time.Second
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
				log.Warn("registerBackground: %v", err)
			}
			ticker.Reset(interval)
		}
	}
}

func (s *Server) register() error {
	var manager server.User
	users := s.Users()
	for _, u := range users {
		if u.Manager {
			manager = u
			break
		}
	}
	users, err := api.Register(s.sweetLisaHost, s.chatIdentifier, model.Server{
		Ticket: s.arg.Ticket,
		Name:   s.arg.Name,
		Host:   s.arg.Host,
		Port:   s.arg.Port,
		Argument: model.Argument{
			Protocol: "shadowsocks",
			Username: manager.Username,
			Password: manager.Password,
			Method:   manager.Method,
		},
	})
	if err != nil {
		return err
	}
	log.Alert("Succeed to register for chat %v at %v", strconv.Quote(s.chatIdentifier), strconv.Quote(s.sweetLisaHost))
	s.lastAlive = time.Now()
	// sweetLisa can replace the manager key here
	if err := s.SyncUsers(users); err != nil {
		return err
	}
	return nil
}

func (s *Server) SyncUsers(users []server.User) (err error) {
	log.Trace("SyncUsers: %v", users)
	toRemove, toAdd := common.Change(s.Users(), users, func(x interface{}) string {
		return x.(server.User).Method + "|" + x.(server.User).Password
	})
	if err := s.RemoveUsers(toRemove.([]server.User), false); err != nil {
		return err
	}
	if err := s.AddUsers(toAdd.([]server.User)); err != nil {
		return err
	}
	return nil
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
				log.Info("handleTCP: %v", err)
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
	var buf [MTU]byte
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
			err := s.handleUDP(lAddr, data, n)
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
	err := s.listener.Close()
	err2 := s.udpConn.Close()
	if err2 != nil {
		return err2
	}
	return err
}

func Users2Keys(users []server.User) (keys []Key, managerKey *Key) {
	keys = make([]Key, len(users))
	for i, u := range users {
		if u.Manager {
			u.Password, _ = gonanoid.Generate(common.Alphabet, 21)
			u.Method = "aes-256-gcm"
			// allow only one manager
			if managerKey == nil {
				keys[i].manager = true
				managerKey = &keys[i]
			}
		}
		keys[i].forwardTo = u.ForwardTo
		keys[i].password = u.Password
		keys[i].method = u.Method
		if keys[i].method == "" {
			keys[i].method = "chacha20-ietf-poly1305"
		}
		conf := CiphersConf[u.Method]
		keys[i].masterKey = EVPBytesToKey(u.Password, conf.KeyLen)
	}
	return keys, managerKey
}

func (s *Server) AddUsers(users []server.User) (err error) {
	log.Trace("AddUsers: %v", users)
	keys, managerKey := Users2Keys(users)
	s.mutex.Lock()
	defer s.mutex.Unlock()
	// update manager key
	if managerKey != nil {
		// remove manager key in UserContext
		s.removeKeysFunc(func(key Key) (remove bool) {
			return key.manager == true
		})
	}
	s.addKeys(keys)
	return nil
}

func (s *Server) RemoveUsers(users []server.User, alsoManager bool) (err error) {
	log.Trace("RemoveUsers: %v, alsoManager: %v", users, alsoManager)
	keys, _ := Users2Keys(users)
	s.mutex.Lock()
	defer s.mutex.Unlock()
	var keySet = make(map[string]struct{})
	for _, key := range keys {
		if key.manager && !alsoManager {
			continue
		}
		k := key.method + "|" + key.password
		keySet[k] = struct{}{}
	}
	s.removeKeysFunc(func(key Key) (remove bool) {
		k := key.method + "|" + key.password
		_, ok := keySet[k]
		return ok
	})
	return nil
}

func (s *Server) Users() (users []server.User) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	for _, k := range s.keys {
		users = append(users, server.User{
			Password: k.password,
			Method:   k.method,
			Manager:  k.manager,
		})
	}
	return users
}

func (s *Server) addKeys(keys []Key) {
	s.keys = append(s.keys, keys...)

	var vals []interface{}
	for _, k := range vals {
		vals = append(vals, k)
	}
	socketIdents := s.userContextPool.Infra().GetKeys()
	for _, ident := range socketIdents {
		userContext := s.userContextPool.Infra().Get(ident).(*UserContext).Infra()
		userContext.Insert(vals)
	}
}

func (s *Server) removeKeysFunc(f func(key Key) (remove bool)) {
	for i := len(s.keys) - 1; i >= 0; i-- {
		if f(s.keys[i]) {
			s.keys = append(s.keys[:i], s.keys[i+1:]...)
		}
	}
	socketIdents := s.userContextPool.Infra().GetKeys()
	for _, ident := range socketIdents {
		userContext := s.userContextPool.Infra().Get(ident).(*UserContext).Infra()
		listCopy := userContext.GetListCopy()
		for _, node := range listCopy {
			if f(node.Val.(Key)) {
				userContext.Remove(node)
			}
		}
		userContext.DestroyListCopy(listCopy)
	}
}
