package cmd

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/common"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/config"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/copyfile"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/log"
	"github.com/google/uuid"
	jsoniter "github.com/json-iterator/go"
	"github.com/manifoldco/promptui"
	"github.com/spf13/cobra"
	"math/rand"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
	"time"
)

var (
	F          embed.FS
	installCmd = &cobra.Command{
		Use:   "install",
		Short: "Install BitterJohn as a systemd service",
		Run: func(cmd *cobra.Command, args []string) {
			user, _ := cmd.Flags().GetBool("user")
			genConfig, _ := cmd.Flags().GetBool("gen-config")
			Install(F, user, genConfig)
		},
	}
)

func init() {
	u, _ := user.Current()
	installCmd.PersistentFlags().BoolP("user", "u", false, fmt.Sprintf("install only for current user (%v)", u.Username))
	installCmd.PersistentFlags().BoolP("gen-config", "g", false, "generate config from user input")
}

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

func getParams(targetConfigPath string) (*config.Params, bool, error) {
	rand.Seed(time.Now().Unix())
	if _, err := os.Stat(targetConfigPath); err != nil {
		if !os.IsNotExist(err) {
			return nil, false, err
		}
		prompt := promptui.Prompt{
			Label:     fmt.Sprintf("The file %v exists. Overwrite?", targetConfigPath),
			IsConfirm: true,
			Default:   "n",
		}
		_, err := prompt.Run()
		if err != nil {
			return nil, false, nil
		}
	}
	prompt := promptui.Prompt{
		Label:    "The host of SweetLisa",
		Validate: hostValidator,
	}
	sweetLisaHost, err := prompt.Run()
	if err != nil {
		return nil, false, err
	}
	//
	//prompt = promptui.Prompt{
	//	Label:    "The CDN token to validate whether SweetLisa can know user's IP",
	//	Validate: minLengthValidatorFactory(5),
	//}
	//validateToken, err := prompt.Run()
	//if err != nil {
	//	return nil, false, err
	//}

	prompt = promptui.Prompt{
		Label:    "Server Ticket",
		Validate: minLengthValidatorFactory(15),
	}
	ticket, err := prompt.Run()
	if err != nil {
		return nil, false, err
	}

	prompt = promptui.Prompt{
		Label:     "Address to listen on",
		Default:   "0.0.0.0:" + strconv.Itoa(1024+rand.Intn(30000)),
		AllowEdit: true,
		Validate:  addressValidator,
	}
	listen, err := prompt.Run()
	if err != nil {
		return nil, false, err
	}
	_, listenPort, err := net.SplitHostPort(listen)
	if err != nil {
		return nil, false, err
	}

	prompt = promptui.Prompt{
		Label:    "Server hostname for users to connect",
		Validate: hostValidator,
	}
	hostname, err := prompt.Run()
	if err != nil {
		return nil, false, err
	}

	prompt = promptui.Prompt{
		Label:     "Server port for users to connect",
		Default:   listenPort,
		Validate:  portValidator,
		AllowEdit: true,
	}
	strPort, err := prompt.Run()
	if err != nil {
		return nil, false, err
	}
	port, _ := strconv.Atoi(strPort)

	prompt = promptui.Prompt{
		Label:    "Server name to register",
		Validate: minLengthValidatorFactory(5),
	}
	name, err := prompt.Run()
	if err != nil {
		return nil, false, err
	}
	return &config.Params{
		Lisa: config.Lisa{
			Host:          sweetLisaHost,
			//ValidateToken: validateToken,
		},
		John: config.John{
			Listen:   listen,
			Name:     name,
			Hostname: hostname,
			Port:     port,
			Ticket:   ticket,
		},
	}, true, nil
}

func writeFiles(f embed.FS, configFilePath string, params *config.Params, serviceFilePath string, binPath string, forUser bool) (err error) {
	var serviceArgs = map[string]interface{}{
		"Bin":     binPath,
		"ForUser": forUser,
	}
	var runningArgs []string
	if params != nil {
		// write config
		b, err := jsoniter.Marshal(params)
		if err != nil {
			return err
		}
		log.Info("Install %v", configFilePath)
		if err = os.WriteFile(configFilePath, b, 0644); err != nil {
			return err
		}
		runningArgs = append(runningArgs, fmt.Sprintf("--config=%v", strconv.Quote(configFilePath)))
	}
	serviceArgs["Args"] = runningArgs

	// render the service file template
	t, _ := template.ParseFS(f, "templates/*")
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "BitterJohn.service", serviceArgs); err != nil {
		return err
	}

	// check the files diff and write service file
	if b, err := os.ReadFile(serviceFilePath); err != nil || !bytes.Equal(b, buf.Bytes()) {
		log.Info("Install %v", serviceFilePath)
		if err = os.WriteFile(serviceFilePath, buf.Bytes(), 0644); err != nil {
			return err
		}
	}
	return nil
}

func Install(f embed.FS, forUser bool, genConfig bool) {
	var (
		targetConfigPath  = "/etc/BitterJohn/BitterJohn.json"
		targetBinPath     = "/usr/bin/BitterJohn"
		targetServicePath = "/usr/lib/systemd/system/BitterJohn.service"
		serviceArgs       = []string{"--now"}
	)
	u, err := user.Current()
	if err != nil {
		log.Fatal("%v", err)
	}
	if forUser {
		targetConfigPath = filepath.Join(u.HomeDir, ".config", "BitterJohn", "BitterJohn.json")
		targetBinPath = filepath.Join(u.HomeDir, "bin", "BitterJohn")
		targetServicePath = filepath.Join(u.HomeDir, ".config", "systemd", "user", "BitterJohn.service")
		serviceArgs = append(serviceArgs, "--user")
	} else if os.Getgid() != 0 {
		log.Warn("This operation may fail without root permission. Please use sudo or add --user flag instead.")
	}
	if genConfig {
		_ = os.MkdirAll(filepath.Dir(targetConfigPath), 0755)
	}
	_ = os.MkdirAll(filepath.Dir(targetBinPath), 0755)
	_ = os.MkdirAll(filepath.Dir(targetServicePath), 0755)
	var (
		params          *config.Params
		overwriteConfig bool
	)
	if genConfig {
		// generate service file
		params, overwriteConfig, err = getParams(targetConfigPath)
		if err != nil {
			log.Fatal("%v", err)
		}
		if !overwriteConfig {
			os.Exit(0)
		}
	}
	// copy binary
	ex, err := os.Executable()
	if err != nil {
		log.Fatal("failed to copy binary: %v", err)
	}
	if ex != targetBinPath {
		log.Info("Install %v", targetBinPath)
		if err = copyfile.CopyFile(ex, targetBinPath); err != nil {
			log.Fatal("failed to copy binary: %v", err)
		}
		_ = os.Chmod(targetBinPath, 0755)
	}
	// write config and systemd service files
	err = writeFiles(f, targetConfigPath, params, targetServicePath, targetBinPath, forUser)
	if err != nil {
		log.Fatal("%v", err)
	}

	log.Info("Installed successfully!")
	log.Info("Run: systemctl enable " + strings.Join(serviceArgs, " ") + " BitterJohn")
}
