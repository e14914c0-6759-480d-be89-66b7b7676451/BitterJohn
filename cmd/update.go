package cmd

import (
	"fmt"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/copyfile"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/log"
	"github.com/spf13/cobra"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

var (
	updateCmd = &cobra.Command{
		Use:   "update",
		Short: "Update only the current binary (no systemd service file)",
		Run: func(cmd *cobra.Command, args []string) {
			Update()
		},
	}
)

func Update() {
	arch := runtime.GOARCH
	switch arch {
	case "arm", "arm64":
	case "amd64":
		arch = "x64"
	case "386":
		arch = "x86"
	default:
		log.Fatal("Unsupported CPU architecture: %v", arch)
	}
	currentBinaryPath, err := os.Executable()
	if err != nil {
		log.Fatal("Failed to get the path of current binary: %v", err)
	}
	f, err := os.CreateTemp("", filepath.Base(currentBinaryPath)+".*")
	if err != nil {
		log.Fatal("Cannot create a temp file: %v", err)
	}
	defer f.Close()
	newBinaryPath := f.Name()
	// download the latest binary
	url := fmt.Sprintf("https://github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/releases/latest/download/BitterJohn_linux_%v", arch)
	log.Info("Download the latest binary from: %v", url)
	resp, err := http.Get(url)
	if err != nil || resp.StatusCode != 200 {
		if err == nil {
			err = fmt.Errorf("bad status: %v (%v)", resp.Status, resp.StatusCode)
		}
		log.Fatal("Failed to download the latest binary: %v", err)
	}
	_, _ = io.Copy(f, resp.Body)
	_ = f.Close()
	// copy binary
	log.Info("Update %v", currentBinaryPath)
	if _, err := os.Stat(currentBinaryPath); err == nil {
		_ = os.Remove(currentBinaryPath)
	}
	if err = copyfile.CopyFile(newBinaryPath, currentBinaryPath); err != nil {
		log.Fatal("Failed to copy binary: %v", err)
	}
	_ = os.Chmod(currentBinaryPath, 0755)
	log.Info("Update completed!")
	cmd := exec.Command(currentBinaryPath, "--version")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	_ = cmd.Run()
	log.Info("If you use systemd, run: systemctl restart BitterJohn.service")
}
