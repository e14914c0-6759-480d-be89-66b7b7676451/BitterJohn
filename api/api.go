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
)

func Register(endpointHost string, info model.Server) (users []server.Passage, err error) {
	if hostname, ok := TrustedHost(endpointHost); !ok {
		cname, _ := net.LookupCNAME(hostname)
		if _, ok = TrustedHost(cname); !ok {
			return nil, fmt.Errorf("untrusted host and cname: %v %v", endpointHost, cname)
		}
	}
	b, err := jsoniter.Marshal(info)
	if err != nil {
		return nil, err
	}
	endpoint := url.URL{
		Scheme: "https",
		Host:   endpointHost,
		Path:   path.Join("api", "ticket", info.Ticket, "register"),
	}
	req, err := http.NewRequestWithContext(context.TODO(), "POST", endpoint.String(), bytes.NewReader(b))
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
		Data    []model.Passage
		Message string
	}
	if err := jsoniter.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		return nil, err
	}
	if respBody.Code != "SUCCESS" {
		return nil, fmt.Errorf(respBody.Message)
	}
	for _, passage := range respBody.Data {
		users = append(users, server.Passage{
			Passage: passage,
			Manager: false,
		})
	}
	return users, nil
}
