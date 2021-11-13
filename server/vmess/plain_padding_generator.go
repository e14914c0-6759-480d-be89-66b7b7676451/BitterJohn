package vmess

import "github.com/v2fly/v2ray-core/v4/common/crypto"

type PlainPaddingGenerator struct {
	crypto.PaddingLengthGenerator
}

func (PlainPaddingGenerator) MaxPaddingLen() uint16 {
	return 0
}

func (PlainPaddingGenerator) NextPaddingLen() uint16 {
	return 0
}
