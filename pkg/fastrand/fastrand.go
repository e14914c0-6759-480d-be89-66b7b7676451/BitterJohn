package fastrand

import (
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/common"
	"math/rand"
)

func init() {
	if err := common.SeedSecurely(); err != nil {
		panic(err)
	}
}

func Intn(n int) int                   { return rand.Intn(n) }
func Float64() float64                 { return rand.Float64() }
func Read(p []byte) (n int, err error) { return rand.Read(p) }
