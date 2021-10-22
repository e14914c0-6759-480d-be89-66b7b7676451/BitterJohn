package cmd

import (
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/config"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/log"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/viperTool"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"os"
	"path/filepath"
	"strings"
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
	var done = make(chan error)

	conf := config.ParamsObj

	// listen
	s, err := server.NewServer("shadowsocks", conf.Lisa, server.Argument{
		Ticket: conf.John.Ticket,
		Name:   conf.John.Name,
		Host:   conf.John.Hostname,
		Port:   conf.John.Port,
	})
	if err != nil {
		log.Fatal("%v", err)
	}
	go func() {
		err = s.Listen(conf.John.Listen)
		done <- err
	}()

	err = <-done
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
	if err := viperTool.NewEnvBinder(v).Bind(config.ParamsObj); err != nil {
		log.Fatal("Fatal error loading config: %s", err)
	}
	if err := v.Unmarshal(&config.ParamsObj); err != nil {
		log.Fatal("Fatal error loading config: %s", err)
	}
	log.Trace("config: %v", v.AllSettings())

	initLog()
}

func initLog() {
	logWay := "console"
	if config.ParamsObj.John.Log.File != "" {
		logWay = "file"
	}
	log.InitLog(logWay, config.ParamsObj.John.Log.File, config.ParamsObj.John.Log.Level, config.ParamsObj.John.Log.MaxDays, config.ParamsObj.John.Log.DisableColor, config.ParamsObj.John.Log.DisableTimestamp)
}
