package common

import (
	"github.com/yl2chen/cidranger"
	"net"
)

var privateCIDR = []string{
	"0.0.0.0/32",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.88.99.0/24",
	"192.168.0.0/16",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"224.0.0.0/4",
	"240.0.0.0/4",
	"::/128",
	"::1/128",
	"64:ff9b:1::/48",
	"100::/64",
	"2001::/32",
	"2001:20::/28",
	"2001:db8::/32",
	"fc00::/7",
	"fe80::/10",
	"ff00::/8",
}

var privateRanger cidranger.Ranger

func init() {
	privateRanger = cidranger.NewPCTrieRanger()
	for _, cidr := range privateCIDR {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(err)
		}
		if err := privateRanger.Insert(cidranger.NewBasicRangerEntry(*ipNet)); err != nil {
			panic(err)
		}
	}
}

func IsPrivate(ip net.IP) bool {
	ok, err := privateRanger.Contains(ip)
	return err == nil && ok
}

func IsPrivateHostname(hostname string) (bool, error) {
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return false, err
	}
	for _, ip := range ips {
		if IsPrivate(ip) {
			return true, nil
		}
	}
	return false, nil
}
