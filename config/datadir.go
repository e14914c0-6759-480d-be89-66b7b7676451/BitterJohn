package config

import (
	"github.com/adrg/xdg"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/log"
	"os"
	"path/filepath"
)

func DataFile(filename string) (string, error) {
	relPath := filepath.Join("BitterJohn", filename)
	fullPath, err := xdg.SearchDataFile(relPath)
	if err != nil {
		if os.Geteuid() == 0 {
			return "/etc/BitterJohn", nil
		}
		log.Info("%v", err)
		fullPath, err = xdg.DataFile(relPath)
		log.Info("%v %v", fullPath, err)
		if err != nil {
			return "", err
		}
	}
	return fullPath, nil
}
