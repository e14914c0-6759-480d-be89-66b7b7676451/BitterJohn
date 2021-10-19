package main

import (
	"embed"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/config"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/log"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server"
	_ "github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server/shadowsocks"
	"os"
)

//go:embed templates/*
var f embed.FS

func main() {
	if len(os.Args) > 1 && os.Args[1] == "install" {
		Install(os.Args, f)
		return
	}

	var done = make(chan error)

	// init config
	conf := config.GetConfig()

	// listen
	s, err := server.NewServer("shadowsocks", conf.SweetLisa, conf.ChatIdentifier, server.Argument{
		Ticket: conf.Ticket,
		Name:   conf.Name,
		Host:   conf.Host,
		Port:   conf.Port,
	})
	if err != nil {
		log.Fatal("%v", err)
	}
	go func() {
		err = s.Listen(conf.Listen)
		done <- err
	}()

	err = <-done
	if err != nil {
		log.Fatal("%v", err)
	}
}
