package config

import (
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/log"
	"github.com/stevenroose/gonfig"
	log2 "log"
	"sync"
)

type Params struct {
	Host                string `id:"host"`
	Port                int    `id:"port"`
	Listen              string `id:"listen" default:"0.0.0.0:8880" desc:"Address to listen at"`
	SweetLisa           string `id:"sweet-lisa" desc:"The host of SweetLisa API endpoint"`
	ChatIdentifier      string `id:"chat-identifier" desc:"The chat identifier to register"`
	Ticket              string `id:"ticket" desc:"Ticket from SweetLisa"`
	Name                string `id:"name" desc:"Server name to register"`
	LogLevel            string `id:"log-level" default:"info" desc:"Optional values: trace, debug, info, warn or error"`
	LogFile             string `id:"log-file" desc:"The path of log file"`
	LogMaxDays          int64  `id:"log-max-days" default:"3" desc:"Maximum number of days to keep log files"`
	LogDisableColor     bool   `id:"log-disable-color"`
	LogDisableTimestamp bool   `id:"log-disable-timestamp"`
}

var params Params
var skipGonfig bool

func initFunc() {
	if !skipGonfig {
		err := gonfig.Load(&params, gonfig.Conf{
			FileDisable:       true,
			FlagIgnoreUnknown: false,
			EnvPrefix:         "JOHN_",
		})
		if err != nil {
			if err.Error() != "unexpected word while parsing flags: '-test.v'" {
				log2.Fatal(err)
			}
		}
	}
	logWay := "console"
	if params.LogFile != "" {
		logWay = "file"
	}
	log.InitLog(logWay, params.LogFile, params.LogLevel, params.LogMaxDays, params.LogDisableColor, params.LogDisableTimestamp)
}

var once sync.Once

func GetConfig() *Params {
	once.Do(initFunc)
	return &params
}

func SetConfig(config Params) {
	skipGonfig = true
	params = config
	return
}
