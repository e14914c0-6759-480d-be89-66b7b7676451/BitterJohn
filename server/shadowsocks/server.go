package shadowsocks

import (
	"errors"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/infra/lru"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/log"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pool"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server"
	"net"
	"strconv"
	"time"
)

const (
	MTU = 65535
)

type Server struct {
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
}

func New(users []server.User) *Server {
	var keys = make([]Key, len(users))
	for i, u := range users {
		keys[i].password = u.Password
		keys[i].method = u.Method
		conf := CiphersConf[u.Method]
		keys[i].masterKey = EVPBytesToKey(u.Password, conf.KeyLen)
	}
	return &Server{
		keys:            keys,
		userContextPool: (*UserContextPool)(lru.New(lru.FixedTimeout, int64(1*time.Hour))),
		nm:              NewUDPConnMapping(),
	}
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
				log.Warn("handleTCP: %v", err)
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
		n, laddr, err := lu.ReadFrom(buf[:])
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
			err := s.handleUDP(laddr, data, n)
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
	err := s.listener.Close()
	err2 := s.udpConn.Close()
	if err2 != nil {
		return err2
	}
	return err
}

//func (s *Server) AddUsers(users []server.User) (err error) {
//
//}
//
//func (s *Server) RemoveUsers(users []server.User) (err error) {
//
//}
//
//func (s *Server) Users() (users []server.User) {
//
//}
