package api

import (
	"bytes"
	"context"
	"fmt"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/SweetLisa/model"
	jsoniter "github.com/json-iterator/go"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"time"
)

func Register(endpointHost, chatIdentifier string, info model.Server) (users []server.User, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	b, err := jsoniter.Marshal(info)
	if err != nil {
		return nil, err
	}
	endpoint := url.URL{
		Scheme: "https",
		Host:   endpointHost,
		Path:   path.Join("api", chatIdentifier, info.Ticket, "register"),
	}
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint.String(), bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	var respBody struct {
		Code    string
		Data    []model.Server
		Message string
	}
	if err := jsoniter.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		return nil, err
	}
	if respBody.Code != "SUCCESS" {
		return nil, fmt.Errorf(respBody.Message)
	}
	for _, u := range respBody.Data {
		var user = server.User{
			Username: u.Argument.Username,
			Password: u.Argument.Password,
			Method:   u.Argument.Method,
			Manager:  false,
		}
		if u.Host != "" {
			user.ForwardTo = net.JoinHostPort(u.Host, strconv.Itoa(u.Port))
		}
		users = append(users, user)
	}
	return users, nil
}
