package protocol

type Header struct {
	ProxyAddress string
	Cipher       string
	Password     string
	IsClient     bool
}
