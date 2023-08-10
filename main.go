package main

import (
	"embed"
	"os"

	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/cmd"
	_ "github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/cdn_validator/cloudflare"
	_ "github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server/juicity"
	_ "github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server/shadowsocks"
	_ "github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server/vmess"
)

//go:embed templates/*
var f embed.FS

func main() {
	cmd.F = f
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
