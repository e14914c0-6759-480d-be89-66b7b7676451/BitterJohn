package cmd

import (
	"context"
	"errors"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/api"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/common"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/config"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/cdn_validator"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/disk_bloom"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/fastrand"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/log"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/viper_tool"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/SweetLisa/model"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/v2fly/v2ray-core/v4/common/antireplay"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

const (
	DiskBloomSalt = "BitterJohn"
)

var (
	runCmd = &cobra.Command{
		Use:   "run",
		Short: "Run BitterJohn in the foreground",
		Run: func(cmd *cobra.Command, args []string) {
			v.BindPFlag("john.log.level", cmd.PersistentFlags().Lookup("log-level"))
			v.BindPFlag("john.log.file", cmd.PersistentFlags().Lookup("log-file"))
			v.BindPFlag("john.log.maxDays", cmd.PersistentFlags().Lookup("log-max-days"))
			v.BindPFlag("john.log.disableTimestamp", cmd.PersistentFlags().Lookup("log-disable-timestamp"))
			v.BindPFlag("john.log.disableColor", cmd.PersistentFlags().Lookup("log-disable-color"))

			Run()
		},
	}
	v = viper.New()
)

func init() {
	runCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file (default is BitterJohn.json)")
	runCmd.PersistentFlags().String("log-level", "", "optional values: trace, debug, info, warn or error (default is warn)")
	runCmd.PersistentFlags().String("log-file", "", "the path of log file")
	runCmd.PersistentFlags().Int64("log-max-days", 0, "maximum number of days to keep log files (default is 3)")
	runCmd.PersistentFlags().Bool("log-disable-timestamp", false, "disable the output of timestamp")
	runCmd.PersistentFlags().Bool("log-disable-color", false, "disable the color of log")
}

func Run() {
	initConfig()
	var err error
	var done = make(chan error)

	conf := config.ParamsObj

	var ctx context.Context
	switch conf.John.Protocol {
	case string(model.ProtocolShadowsocks):
		bloom, err := disk_bloom.NewBloom(filepath.Join(filepath.Dir(v.ConfigFileUsed()), "disk_bloom_*"), []byte(DiskBloomSalt))
		if err != nil {
			log.Fatal("%v", err)
		}
		ctx = context.WithValue(context.Background(), "bloom", bloom)
	case string(model.ProtocolVMessTCP):
		doubleCuckoo := antireplay.NewReplayFilter(120)
		ctx = context.WithValue(context.Background(), "doubleCuckoo", doubleCuckoo)
	}

	// listen
	s, err := server.NewServer(ctx,
		conf.John.Protocol, &conf.Lisa, server.Argument{
			Ticket:    conf.John.Ticket,
			Name:      conf.John.Name,
			Hostnames: conf.John.Hostname,
			Port:      conf.John.Port,
			NoRelay:   conf.John.NoRelay,
		})
	if err != nil {
		log.Fatal("%v", err)
	}
	log.Alert("Protocol: %v", conf.John.Protocol)
	go func() {
		err = s.Listen(conf.John.Listen)
		close(done)
	}()
	go func() {
		// check secrecy of lisa at intervals
		var consecutiveFailure uint32
		for {
			select {
			case <-done:
				break
			default:
			}
			var cdn string
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			t, _ := net.LookupTXT("cdn-validate." + config.ParamsObj.Lisa.Host)
			var validateToken string
			if len(t) > 0 {
				validateToken = t[0]
			}
			cdn, err = api.TrustedHost(ctx, config.ParamsObj.Lisa.Host, validateToken)
			if err != nil {
				if errors.Is(err, cdn_validator.ErrCanStealIP) {
					close(done)
					log.Error("%v: %v", cdn, err)
				} else if errors.Is(err, cdn_validator.ErrFailedValidate) {
					atomic.AddUint32(&consecutiveFailure, 1)
					if consecutiveFailure >= 3 {
						log.Error("%v: %v", cdn, err)
						// TODO: unregister and wait for recover
					}
				}
				log.Warn("%v: %v", cdn, err)
			} else {
				consecutiveFailure = 0
			}
			cancel()
			time.Sleep(time.Duration(fastrand.Intn(181)) * time.Second)
		}
	}()

	<-done
	if err != nil {
		log.Fatal("%v", err)
	}
}

func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		v.SetConfigFile(cfgFile)
	} else {
		v.AddConfigPath("./")
		home, err := os.UserHomeDir()
		if err == nil {
			v.AddConfigPath(filepath.Join(home, "BitterJohn"))
		}
		v.AddConfigPath(filepath.Join("etc", "BitterJohn"))
		v.SetConfigType("json")
		v.SetConfigName("BitterJohn")
	}
	if err := v.ReadInConfig(); err == nil {
		log.Info("Using config file: %v", v.ConfigFileUsed())
	} else if err != nil {
		switch err.(type) {
		default:
			log.Fatal("Fatal error loading config file: %s: %s", v.ConfigFileUsed(), err)
		case viper.ConfigFileNotFoundError:
			log.Warn("No config file found. Using defaults and environment variables")
		}
	}

	// https://github.com/spf13/viper/issues/188
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	if err := viper_tool.NewEnvBinder(v).Bind(config.ParamsObj); err != nil {
		log.Fatal("Fatal error loading config: %s", err)
	}
	if err := v.Unmarshal(&config.ParamsObj); err != nil {
		log.Fatal("Fatal error loading config: %s", err)
	}

	initLog()

	log.Trace("config: %v", v.AllSettings())
}

func initLog() {
	logWay := "console"
	if config.ParamsObj.John.Log.File != "" {
		logWay = "file"
	}
	file, err := common.HomeExpand(config.ParamsObj.John.Log.File)
	if err != nil {
		log.Fatal("%v", err)
	}
	log.InitLog(logWay, file, config.ParamsObj.John.Log.Level, config.ParamsObj.John.Log.MaxDays, config.ParamsObj.John.Log.DisableColor, config.ParamsObj.John.Log.DisableTimestamp)
}
