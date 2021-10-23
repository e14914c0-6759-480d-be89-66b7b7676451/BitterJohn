package cloudflare

import (
	"context"
	"fmt"
	"github.com/cloudflare/cloudflare-go"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/common"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/cdnValidator"
	"strings"
)

var CIDRs = []string{
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
	"2400:cb00::/32",
	"2606:4700::/32",
	"2803:f800::/32",
	"2405:b500::/32",
	"2405:8100::/32",
	"2a06:98c0::/29",
	"2c0f:f248::/32",
}

func init() {
	nets, _ := common.ToIPNets(CIDRs)
	cdnValidator.Register("cloudflare", New, nets)
}

func New(token string) (cdnValidator.CDNValidator, error) {
	api, err := cloudflare.NewWithAPIToken(token)
	if err != nil {
		return nil, err
	}
	return &Cloudflare{api: api}, nil
}

type Cloudflare struct {
	api *cloudflare.API
}

func validRule(r cloudflare.FirewallRule, hostname string) bool {
	return r.Paused == false &&
		r.Action == "block" &&
		r.Filter.Paused == false &&
		(r.Filter.Expression == fmt.Sprintf(`(ip.geoip.country eq "CN" and http.host eq "%v")`, hostname) ||
			r.Filter.Expression == fmt.Sprintf(`(http.host eq "%v" and ip.geoip.country eq "CN")`, hostname))
}

func (c *Cloudflare) Validate(ctx context.Context, domain string) (bool, error) {
	fields := strings.Split(domain, ".")
	if len(fields) < 2 {
		return false, fmt.Errorf("invalid domain: %v", domain)
	}
	zoneName := strings.Join(fields[len(fields)-2:], ".")
	zoneID, err := c.api.ZoneIDByName(zoneName)
	if err != nil {
		return false, err
	}
	rules, err := c.api.FirewallRules(ctx, zoneID, cloudflare.PaginationOptions{})
	for _, rule := range rules {
		if validRule(rule, domain) {
			return true, nil
		}
	}
	return false, err
}
