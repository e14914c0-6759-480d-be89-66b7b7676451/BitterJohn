package cloudflare

import (
	"context"
	"fmt"
	"github.com/cloudflare/cloudflare-go"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/common"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/cdnValidator"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/log"
	path2 "path"
	"strings"
	"time"
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
	ctx, cancel := context.WithTimeout(context.TODO(), 15*time.Second)
	defer cancel()
	v, err := api.VerifyAPIToken(ctx)
	if err != nil {
		return nil, err
	}
	if v.Status != "active" {
		return nil, fmt.Errorf("invalid token")
	}
	return &Cloudflare{api: api}, nil
}

type Cloudflare struct {
	api *cloudflare.API
}

func ValidPageRule(pageRule cloudflare.PageRule, hostname string, path string) bool {
	if pageRule.Status == "active" &&
		len(pageRule.Targets) == 1 &&
		pageRule.Targets[0].Target == "url" &&
		pageRule.Targets[0].Constraint.Operator == "matches" &&
		strings.ReplaceAll(pageRule.Targets[0].Constraint.Value, `\/`, "/") == path2.Join(hostname, path) &&
		len(pageRule.Actions) == 1 &&
		pageRule.Actions[0].ID == "forwarding_url" {
		m, ok := pageRule.Actions[0].Value.(map[string]interface{})
		if !ok {
			log.Warn("pageRule.Actions[0].Value is not map")
			return false
		}
		u, ok := m["url"].(string)
		if !ok {
			log.Warn("pageRule.Actions[0].Value[url] is not string")
			return false
		}
		u = strings.ReplaceAll(u, `\/`, "/")
		return strings.HasPrefix(u, "https://e14914c0-6759-480d-be89-66b7b7676451.github.io/")
	}
	return false
}

func validApiRule(r cloudflare.RulesetRule, hostname string) bool {
	if r.Enabled == true &&
		r.Action == "rewrite" &&
		r.ActionParameters.URI.Path.Value == "/block-cn" &&
		r.ActionParameters.URI.Query.Value == "" &&
		r.Expression == fmt.Sprintf("(ip.geoip.country eq \"CN\" and http.user_agent ne \"BitterJohn\" and http.host eq \"%v\")", hostname) {
		return true
	}
	return false
}

func validHtmlRule(r cloudflare.RulesetRule, hostname string) bool {
	if r.Enabled == true &&
		r.Action == "rewrite" &&
		r.ActionParameters.URI.Path.Value == "/block-cn-html" &&
		r.ActionParameters.URI.Query.Value == "" &&
		r.Expression == fmt.Sprintf("(ip.geoip.country eq \"CN\" and http.user_agent ne \"BitterJohn\" and http.host eq \"%v\" and not http.request.uri.path contains \"/api/\")", hostname) {
		return true
	}
	return false
}

func ValidTransformRuleset(ruleset cloudflare.Ruleset, hostname string) bool {
	if len(ruleset.Rules) != 2 {
		// should be only 2 transform rules
		return false
	}
	if (validApiRule(ruleset.Rules[0], hostname) && validHtmlRule(ruleset.Rules[1], hostname)) ||
		(validApiRule(ruleset.Rules[1], hostname) && validHtmlRule(ruleset.Rules[0], hostname)) {
		return true
	}
	return false
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
	if len(rules) > 0 {
		return false, fmt.Errorf("sweetlisa's cloudflare firewall has rules, which can leave records of the visit")
	}
	var ok bool
	rulesets, err := c.api.ListZoneRulesets(ctx, zoneID)
	if err != nil {
		return false, err
	}
	for _, ruleset := range rulesets {
		if ruleset.Phase != "http_request_transform" {
			continue
		}
		ruleset, err := c.api.GetZoneRuleset(ctx, zoneID, ruleset.ID)
		if err != nil {
			continue
		}
		if ValidTransformRuleset(ruleset, domain) {
			ok = true
			break
		}
	}
	if !ok {
		return false, nil
	}
	var okk = [2]bool{false, false}
	pageRules, err := c.api.ListPageRules(ctx, zoneID)
	if err != nil {
		return false, err
	}
	for _, pageRule := range pageRules {
		if ValidPageRule(pageRule, domain, "block-cn") {
			okk[0] = true
		} else if ValidPageRule(pageRule, domain, "block-cn-html") {
			okk[1] = true
		}
	}
	return okk[0] && okk[1], nil
}
