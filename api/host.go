package api

func TrustedHost(host string) (hostname string, trusted bool) {
	//host = strings.TrimSuffix(host, ".")
	//if strings.Contains(host, ":") {
	//	var err error
	//	host, _, err = net.SplitHostPort(host)
	//	if err != nil {
	//		return host, false
	//	}
	//}
	//for _, trust := range HostWhiteList {
	//	if strings.HasSuffix(host, trust) {
	//		return host, true
	//	}
	//}
	return host, true
}
