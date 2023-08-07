package server

import (
	"time"

	"github.com/e14914c0-6759-480d-be89-66b7b7676451/SweetLisa/model"
)

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
		PassageUseManager: 90 * time.Second,
	}
)

type Passage struct {
	model.Passage
	Manager bool
}

func (p *Passage) Use() (use PassageUse) {
	if p.Manager {
		return PassageUseManager
	} else if p.In.From == "" {
		return PassageUseUser
	} else {
		return PassageUseRelay
	}
}
