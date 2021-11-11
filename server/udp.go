package server

import "time"

const (
	DefaultNatTimeout = 3 * time.Minute
	DnsQueryTimeout   = 17 * time.Second // RFC 5452
)