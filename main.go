package main

import (
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/config"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/log"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server"
	_ "github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server/shadowsocks"
)

func main() {
	// init config
	conf := config.GetConfig()
	s, err := server.NewServer("shadowsocks", []server.User{{Manager: true}})
	if err != nil {
		log.Fatal("%v", err)
	}
	if err = s.Listen(conf.Address); err != nil {
		log.Fatal("%v", err)
	}
}
