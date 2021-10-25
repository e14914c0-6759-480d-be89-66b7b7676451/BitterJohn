package server

import (
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/common"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/log"
)

func SyncPassages(s Server, passages []Passage) (err error) {
	log.Trace("SyncPassages")
	toRemove, toAdd := common.Change(s.Passages(), passages, func(x interface{}) string {
		return x.(Passage).In.Argument.Hash()
	})
	if err := s.RemovePassages(toRemove.([]Passage), false); err != nil {
		return err
	}
	if err := s.AddPassages(toAdd.([]Passage)); err != nil {
		return err
	}
	return nil
}
