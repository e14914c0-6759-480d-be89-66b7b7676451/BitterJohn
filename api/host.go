package api

import (
	"context"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/cdnValidator"
	"net"
	"strings"
)

func TrustedHost(ctx context.Context, host string, validateToken string) (cdnNames string, err error) {
	host = strings.TrimSuffix(host, ".")
	if strings.Contains(host, ":") {
		var err error
		host, _, err = net.SplitHostPort(host)
		if err != nil {
			return "", err
		}
	}
	return cdnValidator.Validate(ctx, host, validateToken)
}
