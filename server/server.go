package server

import (
	"fmt"
	"io"
	"strconv"
)

type Server interface {
	Listen(addr string) (err error)
	AddUsers(users []User) (err error)
	RemoveUsers(users []User) (err error)
	Users() (users []User)
	io.Closer
}

type Creator func(users []User) Server

var Mapper = make(map[string]Creator)

func Register(name string, c Creator) {
	Mapper[name] = c
}

func NewServer(name string, users []User) (Server, error) {
	creator, ok := Mapper[name]
	if !ok {
		return nil, fmt.Errorf("no creator registered for %v", strconv.Quote(name))
	}
	return creator(users), nil
}
