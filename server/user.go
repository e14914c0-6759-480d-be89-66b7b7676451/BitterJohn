package server

import (
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/SweetLisa/model"
	"time"
)

type Passage struct {
	Manager bool
	model.Passage
}
type PassageUse string

const (
	PassageUseUser    PassageUse = "user"
	PassageUseRelay   PassageUse = "relay"
	PassageUseManager PassageUse = "manager"
)

var (
	// ProtectTime is the cooling time of a client IP changing for the same passage
	ProtectTime = map[PassageUse]time.Duration{
		PassageUseUser:    0,
		PassageUseRelay:   90 * time.Second,
		PassageUseManager: 300 * time.Second,
	}
)
