package cdn_validator

import (
	"context"
	"fmt"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/common"
	"net"
	"strings"
)

var (
	ErrNotFound       = fmt.Errorf("this IP is not in our known CDN list")
	ErrCanStealIP     = fmt.Errorf("this domain's setting can steal your IP information")
	ErrFailedValidate = fmt.Errorf("failed to validate")
)

type CDNValidator interface {
	Validate(ctx context.Context, domain string) (bool, error)
}

type Creator func(token string) (CDNValidator, error)
type cdnNet struct {
	name  string
	cidrs []*net.IPNet
}

var validatorMapping = make(map[string]Creator)

var cdnNets []cdnNet

func CreatorByIP(ip net.IP) (string, Creator) {
	for _, n := range cdnNets {
		for _, c := range n.cidrs {
			if c.Contains(ip) {
				return n.name, validatorMapping[n.name]
			}
		}
	}
	return "", nil
}

func Register(name string, creator Creator, cidrs []*net.IPNet) {
	validatorMapping[name] = creator
	cdnNets = append(cdnNets, cdnNet{
		name:  name,
		cidrs: cidrs,
	})
}

func Validate(ctx context.Context, domain string, token string) (cdnName string, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("failed to validate cdn: %w", err)
		}
	}()

	ips, err := net.LookupIP(domain)
	if err != nil {
		return "", err
	}
	// may be served behind multiple CDNs
	var cdnNames []string
	for _, ip := range ips {
		name, creator := CreatorByIP(ip)
		if creator == nil {
			return name, fmt.Errorf("%w: %v", ErrNotFound, ip.String())
		}
		cdnNames = append(cdnNames, name)
	}
	cdnNames = common.Deduplicate(cdnNames)
	for _, name := range cdnNames {
		cdn, err := validatorMapping[name](token)
		if err != nil {
			return name, err
		}
		ok, err := cdn.Validate(ctx, domain)
		if err != nil {
			return name, err
		}
		if !ok {
			return name, ErrCanStealIP
		}
	}
	return strings.Join(cdnNames, ", "), nil
}
