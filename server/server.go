package server

import (
	"context"
	"fmt"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/config"
	"golang.org/x/net/proxy"
	"io"
	"strconv"
	"time"
)

const LostThreshold = 5 * time.Minute

var (
	ErrPassageAbuse = fmt.Errorf("passage abuse")
)

type Argument struct {
	Ticket string

	ServerName string
	Hostnames  string
	Port       int

	NoRelay bool
}

type Server interface {
	Listen(addr string) (err error)
	AddPassages(passages []Passage) (err error)
	RemovePassages(passages []Passage, alsoManager bool) (err error)
	SyncPassages(passages []Passage) (err error)
	Passages() (passages []Passage)
	io.Closer
}

type Creator func(valueCtx context.Context, dialer proxy.Dialer, sweetLisaHost config.Lisa, arg Argument) (Server, error)

var Mapper = make(map[string]Creator)

func Register(name string, c Creator) {
	Mapper[name] = c
}

func NewServer(valueCtx context.Context, dialer proxy.Dialer, protocol string, sweetLisaHost config.Lisa, arg Argument) (Server, error) {
	creator, ok := Mapper[protocol]
	if !ok {
		return nil, fmt.Errorf("no server creator registered for %v", strconv.Quote(protocol))
	}
	return creator(valueCtx, dialer, sweetLisaHost, arg)
}
