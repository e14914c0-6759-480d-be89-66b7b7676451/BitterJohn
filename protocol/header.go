package protocol

type Header struct {
	ProxyAddress string
	SNI          string
	Cipher       string
	Password     string
	IsClient     bool
}
