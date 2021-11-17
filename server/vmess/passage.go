package vmess

import (
	"crypto/cipher"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server"
)

type Passage struct {
	server.Passage

	inCmdKey      []byte
	outCmdKey     []byte

	inEAuthIDBlock cipher.Block
}
