package cmd

import (
	"context"
	"errors"
	"fmt"
	"github.com/daeuniverse/softwind/netproxy"
	"github.com/daeuniverse/softwind/pkg/fastrand"
	"github.com/daeuniverse/softwind/protocol"
	"github.com/daeuniverse/softwind/protocol/shadowsocks"
	"github.com/daeuniverse/softwind/protocol/vmess"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/api"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/common"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/config"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/cdn_validator"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/disk_bloom"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/log"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/resolver"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/viper_tool"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"net"
	"os"
	"path/filepath"
	"strconv"
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
			v.BindPFlag("john.doNotValidateCDN", cmd.PersistentFlags().Lookup("do-not-validate-cdn"))

			if err := Run(); err != nil {
				log.Fatal("%v", err)
			}
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
	runCmd.PersistentFlags().Bool("do-not-validate-cdn", false, "do not validate the CDN configuration of the peer SweetLisa")
}

func Run() (err error) {
	initConfig()

	server.InitLimitedDialer()

	shadowsocks.DefaultIodizedSource = "https://autumn-cell-a7f2.tuta.cc/explore"

	var done = make(chan error)

	conf := &config.ParamsObj

	var (
		ctx    context.Context
		dialer netproxy.Dialer
	)
	if !protocol.Protocol(conf.John.Protocol).Valid() {
		return fmt.Errorf("protocol %v is invalid", strconv.Quote(conf.John.Protocol))
	}
	switch proto := protocol.Protocol(conf.John.Protocol); proto {
	case protocol.ProtocolShadowsocks:
		bloom, err := disk_bloom.NewBloom(filepath.Join(filepath.Dir(v.ConfigFileUsed()), "disk_bloom_*"), []byte(DiskBloomSalt))
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		ctx = context.WithValue(context.Background(), "bloom", bloom)
		dialer = server.FullconePrivateLimitedDialer
	case protocol.ProtocolVMessTCP, protocol.ProtocolVMessTlsGrpc:
		doubleCuckoo := vmess.NewReplayFilter(120)
		ctx = context.WithValue(context.Background(), "doubleCuckoo", doubleCuckoo)
		dialer = server.FullconePrivateLimitedDialer
	}

	// listen
	s, err := server.NewServer(ctx, dialer,
		conf.John.Protocol, conf.Lisa, server.Argument{
			Ticket:     conf.John.Ticket,
			ServerName: conf.John.Name,
			Hostnames:  conf.John.Hostname,
			Port:       conf.John.Port,
			NoRelay:    conf.John.NoRelay,
		})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	log.Alert("Protocol: %v", conf.John.Protocol)
	if common.StringsHas(strings.Split(conf.John.Protocol, "+"), "tls") {
		// waiting for the record
		domain, err := common.HostsToSNI(conf.John.Hostname, conf.Lisa.Host)
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		log.Info("TLS SNI is %v", domain)

		log.Alert("Waiting for DNS record")
		t := time.Now()
		for {
			ips, _ := resolver.LookupHost(domain)
			if len(ips) > 0 {
				break
			}
			if time.Since(t) > time.Minute {
				return fmt.Errorf("timeout for waiting for DNS record")
			}
			time.Sleep(500 * time.Millisecond)
		}
		log.Alert("Found DNS record")
	}
	go func() {
		err = s.Listen(conf.John.Listen)
		close(done)
	}()

	if !config.ParamsObj.John.DoNotValidateCDN {
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
					switch {
					case strings.Contains(err.Error(), "context deadline exceeded"):
						// pass
						log.Warn("%v: %v", cdn, err)
					case errors.Is(err, cdn_validator.ErrCanStealIP):
						close(done)
						log.Error("%v: %v", cdn, err)
					case errors.Is(err, cdn_validator.ErrFailedValidate):
						atomic.AddUint32(&consecutiveFailure, 1)
						if consecutiveFailure >= 3 {
							log.Error("%v: %v", cdn, err)
							// TODO: unregister and wait for recover
						}
					}
				} else {
					consecutiveFailure = 0
				}
				cancel()
				time.Sleep(30*time.Second + time.Duration(fastrand.Intn(151))*time.Second)
			}
		}()
	}

	<-done
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	return nil
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
