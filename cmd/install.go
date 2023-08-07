package cmd

import (
	"bufio"
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"github.com/AlecAivazis/survey/v2"
	"github.com/daeuniverse/softwind/pkg/fastrand"
	"github.com/daeuniverse/softwind/protocol"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/common"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/config"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/copyfile"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/log"
	"github.com/spf13/cobra"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"
)

var (
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

func hostsValidator(ans interface{}) error {
	str := ans.(string)
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

func hostValidator(ans interface{}) error {
	str := ans.(string)
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

func portValidator(ans interface{}) error {
	str := ans.(string)
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

func dayValidator(ans interface{}) error {
	str := ans.(string)
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

func uint64Validator(ans interface{}) error {
	str := ans.(string)
	e := fmt.Errorf("Invalid Uint64")
	_, err := strconv.ParseUint(str, 10, 64)
	if err != nil {
		return e
	}
	return nil
}

func limitValidator(ans interface{}) error {
	str := ans.(string)
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

func minLengthValidatorFactory(minLength int) survey.Validator {
	return func(ans interface{}) error {
		str := ans.(string)
		e := fmt.Errorf("Too short")
		if len(str) < minLength {
			return e
		}
		return nil
	}
}

func addressValidator(ans interface{}) error {
	str := ans.(string)
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

func getIP(client *http.Client) (ip string) {
	resp, err := client.Get("https://api.cloudflare.com/cdn-cgi/trace")
	if err == nil {
		if resp.StatusCode == 200 {
			scanner := bufio.NewScanner(resp.Body)
			for scanner.Scan() {
				if strings.HasPrefix(scanner.Text(), "ip=") {
					ip = strings.TrimPrefix(scanner.Text(), "ip=")
					break
				}
			}
			_ = resp.Body.Close()
		}
	}
	return ip
}

func getDefaultHostnames() (hostnames string) {
	var (
		timeout          = 5 * time.Second
		netDefaultDialer net.Dialer
		c4               = http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return netDefaultDialer.DialContext(ctx, "tcp4", addr)
				},
			},
			Timeout: timeout,
		}
		c6 = http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return netDefaultDialer.DialContext(ctx, "tcp6", addr)
				},
			},
			Timeout: timeout,
		}
		ips [2]string
		wg  sync.WaitGroup
	)
	wg.Add(2)
	go func() {
		ips[0] = getIP(&c4)
		wg.Done()
	}()
	go func() {
		ips[1] = getIP(&c6)
		wg.Done()
	}()
	wg.Wait()
	return strings.Join(common.Deduplicate(common.RemoveEmpty(ips[:])), ",")
}

func getParams(targetConfigPath string) (*config.Params, bool, error) {
	if _, err := os.Stat(targetConfigPath); err != nil && !os.IsNotExist(err) {
		return nil, false, err
	} else if err == nil {
		var overwrite bool
		survey.AskOne(&survey.Confirm{
			Message: fmt.Sprintf("The file %v exists. Overwrite?", targetConfigPath),
		}, &overwrite)
		if !overwrite {
			return nil, false, nil
		}
	}

	var (
		proto         string
		sweetLisaHost string
		ticket        string
		listen        string
		hostname      string
		strPort       string
		name          string
	)
	if err := survey.AskOne(&survey.Select{
		Message: "Portocol:",
		Default: "vmess+tls+grpc",
		Options: []string{"vmess", "vmess+tls+grpc", "shadowsocks"},
	}, &proto, survey.WithValidator(survey.Required)); err != nil {
		return nil, false, err
	}
	if err := survey.AskOne(&survey.Input{
		Message: "The host of SweetLisa:",
		Default: "sweetlisa.tuta.cc",
	}, &sweetLisaHost, survey.WithValidator(hostValidator)); err != nil {
		return nil, false, err
	}
	if err := survey.AskOne(&survey.Input{
		Message: "Server Ticket:",
		Help:    "You can get the ticket by @SweetLisa_bot. Send \"/sweetlisa\" to your anonymous channel.",
	}, &ticket, survey.WithValidator(minLengthValidatorFactory(15))); err != nil {
		return nil, false, err
	}
	randPort := strconv.Itoa(1024 + fastrand.Intn(30000))
	if proto == string(protocol.ProtocolVMessTlsGrpc) {
		randPort = "50051"
	}
	if err := survey.AskOne(&survey.Input{
		Message: "Address to listen on:",
		Default: "0.0.0.0:" + randPort,
		Help: "The local address you want to listen. Protocols contain \"tls\" will occupy more one port 80. " +
			"Make sure the ports are available.",
	}, &listen, survey.WithValidator(addressValidator)); err != nil {
		return nil, false, err
	}
	_, listenPort, err := net.SplitHostPort(listen)
	if err != nil {
		return nil, false, err
	}
	if err := survey.AskOne(&survey.Input{
		Message: "Server hostname for users to connect (split by \",\"):",
		Default: getDefaultHostnames(),
		Help: "It could be domain, IPv4 or IPv6. You may have multiple hostnames for users to connects; " +
			"join them by \",\" like \"example.com,1.1.1.1,2001:470e::483\". " +
			"The first hostname is for SweetLisa to connect, verify and check health.",
	}, &hostname, survey.WithValidator(hostsValidator)); err != nil {
		return nil, false, err
	}
	if err := survey.AskOne(&survey.Input{
		Message: "Server port for users to connect:",
		Default: listenPort,
		Help: "The port for users to connect. It can be different from the listened port and this feature is useful " +
			"for machines behind NAT.",
	}, &strPort, survey.WithValidator(portValidator)); err != nil {
		return nil, false, err
	}
	port, _ := strconv.Atoi(strPort)
	if err := survey.AskOne(&survey.Input{
		Message: "Server name to register:",
		Help:    "This name is showed in the subscription as the server name.",
	}, &name, survey.WithValidator(minLengthValidatorFactory(5))); err != nil {
		return nil, false, err
	}
	var (
		needRelay bool
		strDay    string
		strLimit  string

		noRelay              bool
		enableBandwidthLimit bool
		resetDay             uint8
		uplinkLimitGiB       int64
		downlinkLimitGiB     int64
		totalLimitGiB        int64
	)

	if err := survey.AskOne(&survey.Confirm{
		Message: "This machine doesn't need relays? [n (no relays) / Y (need relays)]",
		Default: true,
		Help:    "This option is only valid for endpoint machine.",
	}, &needRelay); err != nil {
		return nil, false, err
	}
	noRelay = !needRelay
	if err := survey.AskOne(&survey.Confirm{
		Message: "Do you want to set traffic limit?",
		Default: false,
		Help: "If yes, SweetLisa will show the remaining quota in the server name and disconnect the machine when " +
			"the quota is exhausted.",
	}, &enableBandwidthLimit); err != nil {
		return nil, false, err
	}
	if enableBandwidthLimit {
		if err := survey.AskOne(&survey.Input{
			Message: "The day of every month to reset the limit of traffic:",
			Default: "1",
			Help:    "For example, if it is set 5, the quota will be reset on the 5th of every month.",
		}, &strDay, survey.WithValidator(dayValidator)); err != nil {
			return nil, false, err
		}
		resetDay = common.ShouldParseUint8(strDay)
		if err := survey.AskOne(&survey.Input{
			Message: "UplinkLimitGB/DownlinkLimitGB/TotalLimitGB (example: 980/0/0, zero means no limit):",
			Default: "0/0/0",
			Help: "UplinkLimit, DownlinkLimit and TotalLimit can be set respectively. Any of them is exhausted will " +
				"trigger the traffic protection.",
		}, &strLimit, survey.WithValidator(limitValidator)); err != nil {
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
			Protocol: proto,
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
		b, err := json.MarshalIndent(params, "", "\t")
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
	log.Info("Run: systemctl enable " + strings.Join(serviceArgs, " ") + " BitterJohn.service")
}
