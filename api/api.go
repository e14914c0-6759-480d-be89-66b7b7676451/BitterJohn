package api

import (
	"bytes"
	"context"
	"fmt"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/SweetLisa/model"
	jsoniter "github.com/json-iterator/go"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
)

func Register(ctx context.Context, endpointHost string, validateToken string, info model.Server) (cdnNames string, users []server.Passage, err error) {
	if cdnNames, err = TrustedHost(ctx, endpointHost, validateToken); err != nil {
		return cdnNames, nil, err
	}
	b, err := jsoniter.Marshal(info)
	if err != nil {
		return cdnNames, nil, err
	}
	u := url.URL{
		Scheme: "https",
		Host:   endpointHost,
		Path:   path.Join("api", "ticket", info.Ticket, "register"),
	}
	req, err := http.NewRequestWithContext(ctx, "POST", u.String(), bytes.NewReader(b))
	if err != nil {
		return cdnNames, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "BitterJohn")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return cdnNames, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return "", nil, fmt.Errorf("SweetLisa responsed with %v: %v", strconv.Quote(resp.Status), string(b))
	}
	var respBody struct {
		Code    string
		Data    []model.Passage
		Message string
	}
	if err := jsoniter.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		return cdnNames, nil, err
	}
	if respBody.Code != "SUCCESS" {
		return cdnNames, nil, fmt.Errorf(respBody.Message)
	}
	for _, passage := range respBody.Data {
		users = append(users, server.Passage{
			Passage: passage,
			Manager: false,
		})
	}
	return cdnNames, users, nil
}
