package shadowsocks

import (
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/infra/lru"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/log"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server"
	"net"
	"time"
)

type Shadowsocks struct {
	keys            []Key
	userContextPool *UserContextPool
	listener        net.Listener
	udpConn         *net.UDPConn
}

type Key struct {
	password  string
	method    string
	masterKey []byte
}

func New(users []server.User) *Shadowsocks {
	var keys = make([]Key, len(users))
	for i, u := range users {
		keys[i].password = u.Password
		keys[i].method = u.Method
		conf := CiphersConf[u.Method]
		keys[i].masterKey = EVPBytesToKey(u.Password, conf.KeyLen)
	}
	return &Shadowsocks{
		keys:            keys,
		userContextPool: (*UserContextPool)(lru.New(lru.FixedTimeout, int64(1*time.Hour))),
	}
}

func (s *Shadowsocks) Listen(addr string) (err error) {
	//_, strPort, err := net.SplitHostPort(addr)
	//if err != nil {
	//	return err
	//}
	//port, err := strconv.Atoi(strPort)
	//if err != nil {
	//	return err
	//}
	lt, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	//lu, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
	//if err != nil {
	//	return err
	//}
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
	//for {
	//	conn, err := lu.Read()
	//	if err != nil {
	//		log.Warn("%v", err)
	//	}
	//	go handleUDP(conn.(*net.UDPConn))
	//}
}

//func (s *Shadowsocks) AddUsers(users []server.User) (err error) {
//
//}
//
//func (s *Shadowsocks) RemoveUsers(users []server.User) (err error) {
//
//}
//
//func (s *Shadowsocks) Users() (users []server.User) {
//
//}
