package main

import (
	"bytes"
	"context"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/config"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/log"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server"
	_ "github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server/shadowsocks"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/SweetLisa/model"
	jsoniter "github.com/json-iterator/go"
	"net/http"
	"time"
)

func main() {
	var done = make(chan error)

	// init config
	conf := config.GetConfig()

	// listen
	s, err := server.NewServer("shadowsocks", []server.User{{Manager: true}, {Password: "1"}, {Password: "2"}})
	if err != nil {
		log.Fatal("%v", err)
	}
	go func() {
		err = s.Listen(conf.Listen)
		done <- err
	}()

	// connect to SweetLisa and register
	var manager server.User
	for _, u := range s.Users() {
		if u.Manager {
			manager = u
			break
		}
	}
	users, err := Register(manager)
	if err != nil {
		log.Fatal("%v", err)
	}
	if err = s.AddUsers(users); err != nil {
		log.Fatal("%v", err)
	}

	err = <-done
	if err != nil {
		log.Fatal("%v", err)
	}
}

func Register(manager server.User) (users []server.User, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conf := config.GetConfig()
	var reqBody = model.Server{
		Ticket: conf.Ticket,
		Name:   conf.Name,
		Host:   conf.Host,
		Port:   conf.Port,
		ManageArgument: model.Argument{
			Protocol: "shadowsocks",
			Username: manager.Username,
			Password: manager.Password,
			Method:   manager.Method,
		},
	}
	b, err := jsoniter.Marshal(reqBody)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", conf.SweetLisa, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	var sUsers []model.Argument
	if err := jsoniter.NewDecoder(resp.Body).Decode(&sUsers); err != nil {
		return nil, err
	}
	for _, u := range sUsers {
		users = append(users, server.User{
			Username: u.Username,
			Password: u.Password,
			Method:   u.Method,
			Manager:  false,
		})
	}
	return users, nil
}
