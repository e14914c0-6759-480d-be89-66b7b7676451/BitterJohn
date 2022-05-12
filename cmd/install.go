package cmd

import (
	"bufio"
	"bytes"
	"context"
	"embed"
	"fmt"
	"github.com/1lann/promptui"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/common"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/config"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/copyfile"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/fastrand"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/log"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/SweetLisa/model"
	"github.com/google/uuid"
	jsoniter "github.com/json-iterator/go"
	"github.com/spf13/cobra"
	"net"
	"net/http"
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

func hostsValidator(str string) error {
	if len(str) == 0 {
		return fmt.Errorf("host length cannot be zero")
	}
	hosts := strings.Split(str, ",")
	for _, host := range hosts {
		if err := hostValidator(host); err != nil {
			return fmt.Errorf("%v: %w", host, err)
		}
	}
	return nil
}

func hostValidator(str string) error {
	e := fmt.Errorf("Invalid Hostname")
	if net.ParseIP(str) != nil {
		return nil
	} else if !common.HasTopDomain(str) {
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

func dayValidator(str string) error {
	e := fmt.Errorf("Invalid Day")
	day, err := strconv.Atoi(str)
	if err != nil {
		return e
	}
	if day > 31 || day <= 0 {
		return e
	}
	return nil
}

func uint64Validator(str string) error {
	e := fmt.Errorf("Invalid Uint64")
	_, err := strconv.ParseUint(str, 10, 64)
	if err != nil {
		return e
	}
	return nil
}

func limitValidator(str string) error {
	e := fmt.Errorf("Invalid Limit Format")
	if len(str) == 0 {
		return e
	}
	fields := strings.Split(str, "/")
	if len(fields) != 3 {
		return e
	}
	for _, f := range fields {
		if err := uint64Validator(f); err != nil {
			return err
		}
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
	if _, err := os.Stat(targetConfigPath); err != nil && !os.IsNotExist(err) {
		return nil, false, err
	} else if err == nil {
		prompt := &promptui.Prompt{
			Label:     fmt.Sprintf("The file %v exists. Overwrite", targetConfigPath),
			IsConfirm: true,
		}
		_, err := prompt.Run()
		if err != nil {
			return nil, false, nil
		}
	}

	sel := &promptui.Select{
		Label: "Protocol",
		Items: []string{"vmess", "vmess+tls+grpc", "shadowsocks"},
	}
	_, protocol, err := sel.Run()

	prompt := &promptui.Prompt{
		Label:    "The host of SweetLisa",
		Validate: hostValidator,
		Default:  "sweetlisa.tuta.cc",
	}
	sweetLisaHost, err := prompt.Run()
	if err != nil {
		return nil, false, err
	}

	prompt = &promptui.Prompt{
		Label:    "Server Ticket",
		Validate: minLengthValidatorFactory(15),
	}
	ticket, err := prompt.Run()
	if err != nil {
		return nil, false, err
	}

	randPort := strconv.Itoa(1024 + fastrand.Intn(30000))
	if protocol == string(model.ProtocolVMessTlsGrpc) {
		randPort = "50051"
	}
	prompt = &promptui.Prompt{
		Label:     "Address to listen on",
		Default:   "0.0.0.0:" + randPort,
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
	var hostname string
	resp, err := http.Get("https://api.cloudflare.com/cdn-cgi/trace")
	if err == nil {
		if resp.StatusCode == 200 {
			scanner := bufio.NewScanner(resp.Body)
			for scanner.Scan() {
				if strings.HasPrefix(scanner.Text(), "ip=") {
					hostname = strings.TrimPrefix(scanner.Text(), "ip=")
					break
				}
			}
			_ = resp.Body.Close()
		}
	}
	prompt = &promptui.Prompt{
		Label:    "Server hostname for users to connect (split by \",\")",
		Default:  hostname,
		Validate: hostsValidator,
	}
	hostname, err = prompt.Run()
	if err != nil {
		return nil, false, err
	}

	prompt = &promptui.Prompt{
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

	prompt = &promptui.Prompt{
		Label:    "Server name to register",
		Validate: minLengthValidatorFactory(5),
	}
	name, err := prompt.Run()
	if err != nil {
		return nil, false, err
	}
	var (
		enableBandwidthLimit bool
		resetDay             uint8
		uplinkLimitGiB       int64
		downlinkLimitGiB     int64
		totalLimitGiB        int64
	)

	var noRelay bool
	prompt = &promptui.Prompt{
		Label:     "This machine doesn't need relays? [n (no relays) / Y (need relays)]",
		IsConfirm: true,
		Default:   "y",
	}
	_, err = prompt.Run()
	if err != nil {
		noRelay = true
	}

	prompt = &promptui.Prompt{
		Label:     "Do you want to set bandwidth limit",
		IsConfirm: true,
	}
	_, err = prompt.Run()
	if err == nil {
		enableBandwidthLimit = true

		prompt = &promptui.Prompt{
			Label:    "The day of every month to reset the limit of bandwidth",
			Default:  "1",
			Validate: dayValidator,
		}
		strDay, err := prompt.Run()
		if err != nil {
			return nil, false, err
		}
		resetDay = common.ShouldParseUint8(strDay)
		prompt = &promptui.Prompt{
			Label:     "UplinkLimitGiB/DownlinkLimitGiB/TotalLimitGiB (example: 980/0/0, zero means no limit)",
			Default:   "0/0/0",
			AllowEdit: true,
			Validate:  limitValidator,
		}
		strLimit, err := prompt.Run()
		if err != nil {
			return nil, false, err
		}
		fields := strings.Split(strLimit, "/")
		uplinkLimitGiB = common.ShouldParseInt64(fields[0])
		downlinkLimitGiB = common.ShouldParseInt64(fields[1])
		totalLimitGiB = common.ShouldParseInt64(fields[2])
	}

	return &config.Params{
		Lisa: config.Lisa{
			Host: sweetLisaHost,
			//ValidateToken: validateToken,
		},
		John: config.John{
			Listen:   listen,
			Name:     name,
			Hostname: hostname,
			Port:     port,
			Ticket:   ticket,
			BandwidthLimit: config.BandwidthLimit{
				Enable:           enableBandwidthLimit,
				ResetDay:         resetDay,
				UplinkLimitGiB:   uplinkLimitGiB,
				DownlinkLimitGiB: downlinkLimitGiB,
				TotalLimitGiB:    totalLimitGiB,
			},
			NoRelay:  noRelay,
			Protocol: protocol,
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
		// WARN: do not escape here to be compatible with linux 3.10
		runningArgs = append(runningArgs, fmt.Sprintf("--config=%v", configFilePath))
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
		if _, err := os.Stat(targetBinPath); err == nil {
			_ = os.Remove(targetBinPath)
		}
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
