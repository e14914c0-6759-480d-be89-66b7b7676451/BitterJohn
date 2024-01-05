package server

import (
	"net"
	"sync"
	"time"
)

type ContentionCache struct {
	mu sync.Mutex
	m  map[string]ContentionCountdown
}

type ContentionCountdown struct {
	countdown       *time.Timer
	ip              net.IP
	protectDeadline time.Time
}

func NewContentionCache() *ContentionCache {
	return &ContentionCache{
		m: make(map[string]ContentionCountdown),
	}
}

// Check return if the IP should be allowed for the key.
func (c *ContentionCache) Check(key string, protectTime time.Duration, ip net.IP) (accept bool, conflictIP net.IP) {
	// Do not limit the different IPs.
	return true
	if protectTime == 0 {
		return true, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var write bool
	v, ok := c.m[key]
	if !ok {
		write = true
	} else if v.ip.Equal(ip) {
		c.m[key].countdown.Reset(protectTime)
	} else if time.Now().After(v.protectDeadline) {
		write = true
	} else {
		return false, v.ip
	}
	if write {
		c.m[key] = ContentionCountdown{
			countdown: time.AfterFunc(protectTime, func() {
				c.mu.Lock()
				delete(c.m, key)
				c.mu.Unlock()
			}),
			ip:              ip,
			protectDeadline: time.Now().Add(protectTime),
		}
	}
	return true, nil
}
