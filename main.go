package main

import (
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/config"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/log"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server/shadowsocks"
)

func main() {
	// init config
	config.GetConfig()

	log.Fatal("%v",
		shadowsocks.New([]server.User{
			{
				Password: "justtestit",
				Method:   "chacha20-ietf-poly1305",
			},
		}).Listen("0.0.0.0:8880"))
}
