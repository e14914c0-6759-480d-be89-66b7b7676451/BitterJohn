package main

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/common"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/config"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/copyfile"
	"github.com/google/uuid"
	"github.com/manifoldco/promptui"
	"log"
	"math/rand"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"
	"text/template"
	"time"
)

func hostValidator(str string) error {
	e := fmt.Errorf("Invalid Host")
	if net.ParseIP(str) == nil && !common.HasTopDomain(str) {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, str)
	if err != nil {
		return e
	}
	if len(addrs) == 0 {
		return e
	}
	return nil
}

func portValidator(str string) error {
	e := fmt.Errorf("Invalid Port")
	port, err := strconv.Atoi(str)
	if err != nil {
		return e
	}
	if port > 65535 || port < 0 {
		return e
	}
	return nil
}

func uuidValidator(str string) error {
	e := fmt.Errorf("Invalid ChatIdentifier")
	if _, err := uuid.Parse(str); err != nil {
		return e
	}
	return nil
}

func minLengthValidatorFactory(minLength int) promptui.ValidateFunc {
	return func(str string) error {
		e := fmt.Errorf("Too short")
		if len(str) < minLength {
			return e
		}
		return nil
	}
}

func addressValidator(str string) error {
	e := fmt.Errorf("Invalid Adderss")
	host, port, err := net.SplitHostPort(str)
	if err != nil {
		return e
	}
	if net.ParseIP(host) == nil {
		return e
	}
	return portValidator(port)
}

func getParams() (*config.Params, error) {
	rand.Seed(time.Now().Unix())
	prompt := promptui.Prompt{
		Label:    "Host of Sweet Lisa",
		Validate: hostValidator,
	}
	sweetLisaHost, err := prompt.Run()
	if err != nil {
		return nil, err
	}
	prompt = promptui.Prompt{
		Label:    "Chat Identifier",
		Validate: uuidValidator,
	}
	chatIdentifier, err := prompt.Run()
	if err != nil {
		return nil, err
	}
	sel := promptui.Select{
		Label: "Server Type",
		Items: []string{
			"Server",
			//"Relay",
		},
	}
	_, _, err = sel.Run()
	if err != nil {
		return nil, err
	}

	prompt = promptui.Prompt{
		Label:    "Server Ticket",
		Validate: minLengthValidatorFactory(15),
	}
	ticket, err := prompt.Run()
	if err != nil {
		return nil, err
	}

	prompt = promptui.Prompt{
		Label:     "Address to listen on",
		Default:   "0.0.0.0:" + strconv.Itoa(1024+rand.Intn(30000)),
		AllowEdit: true,
		Validate:  addressValidator,
	}
	address, err := prompt.Run()
	if err != nil {
		return nil, err
	}
	_, listenPort, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	prompt = promptui.Prompt{
		Label:    "Host to show",
		Validate: hostValidator,
	}
	host, err := prompt.Run()
	if err != nil {
		return nil, err
	}

	prompt = promptui.Prompt{
		Label:     "Port to show",
		Default:   listenPort,
		Validate:  portValidator,
		AllowEdit: true,
	}
	strPort, err := prompt.Run()
	if err != nil {
		return nil, err
	}
	port, _ := strconv.Atoi(strPort)

	prompt = promptui.Prompt{
		Label:    "Server Name to show",
		Validate: minLengthValidatorFactory(5),
	}
	name, err := prompt.Run()
	if err != nil {
		return nil, err
	}
	return &config.Params{
		Host:           host,
		Port:           port,
		Listen:         address,
		SweetLisa:      sweetLisaHost,
		ChatIdentifier: chatIdentifier,
		Ticket:         ticket,
		Name:           name,
	}, nil
}

func generateServiceFile(f embed.FS, params *config.Params) ([]byte, error) {
	type Env struct {
		Name  string
		Value string
	}
	var envs []Env
	val := reflect.ValueOf(params).Elem()
	typ := reflect.TypeOf(params).Elem()
	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		name := typ.Field(i).Tag.Get("id")
		name = strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
		name = "JOHN_" + name

		if field.IsZero() {
			continue
		}
		value := fmt.Sprintf("%v", field.Interface())
		if len(value) == 0 {
			continue
		}
		envs = append(envs, Env{
			Name:  name,
			Value: value,
		})
	}
	t, _ := template.ParseFS(f, "templates/*")
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "BitterJohn.service", map[string]interface{}{
		"Envs": envs,
	}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func Install(args []string, f embed.FS) {
	// copy binary
	const TargetBinPath = "/usr/bin/BitterJohn"
	if args[0] != TargetBinPath {
		if err := copyfile.CopyFile(args[0], TargetBinPath); err != nil {
			log.Fatal(fmt.Errorf("failed to copy binary: %w", err))
			return
		}
	}

	// generate service file
	params, err := getParams()
	if err != nil {
		log.Fatal(err)
	}
	b, err := generateServiceFile(f, params)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile("/usr/lib/systemd/system/BitterJohn.service", b, 0644); err != nil {
		log.Fatal(err)
	}
	log.Println("Installed successfully!")
	log.Println("Run: systemctl enable --now BitterJohn")
	return
}
