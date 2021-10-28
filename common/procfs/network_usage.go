package procfs

import (
	"fmt"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/common"
	"os"
	"strings"
)

const (
	NetDev = "/proc/net/dev"
)

type TxRx struct {
	InterfaceName string

	RxBytes      int64
	RxPackets    int64
	RxErrs       int64
	RxDropMiss   int64
	RxFifoErrs   int64
	RxFrameErrs  int64
	RxCompressed int64

	TxBytes       int64
	TxPackets     int64
	TxErrs        int64
	TxDropMiss    int64
	TxFifoErrs    int64
	TxCarrierErrs int64
	TxCompressed  int64

	Collisions int64
	Multicast  int64
}

func InterfacesTxRx() (txRxes []TxRx, err error) {
	b, err := os.ReadFile(NetDev)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(b), "\n")[2:]
	expectedFields := 17
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) != expectedFields {
			return nil, fmt.Errorf("failed to parse %v: has %v fields, but expected %v: %v", NetDev, len(f), expectedFields, f)
		}
		txRxes = append(txRxes, TxRx{
			InterfaceName: strings.TrimSuffix(f[0], ":"),
			RxBytes:       common.ShouldParseInt64(f[1]),
			RxPackets:     common.ShouldParseInt64(f[2]),
			RxErrs:        common.ShouldParseInt64(f[3]),
			RxDropMiss:    common.ShouldParseInt64(f[4]),
			RxFifoErrs:    common.ShouldParseInt64(f[5]),
			RxFrameErrs:   common.ShouldParseInt64(f[6]),
			RxCompressed:  common.ShouldParseInt64(f[7]),
			TxBytes:       common.ShouldParseInt64(f[9]),
			TxPackets:     common.ShouldParseInt64(f[10]),
			TxErrs:        common.ShouldParseInt64(f[11]),
			TxDropMiss:    common.ShouldParseInt64(f[12]),
			TxFifoErrs:    common.ShouldParseInt64(f[13]),
			TxCarrierErrs: common.ShouldParseInt64(f[15]),
			TxCompressed:  common.ShouldParseInt64(f[16]),
			Collisions:    common.ShouldParseInt64(f[14]),
			Multicast:     common.ShouldParseInt64(f[8]),
		})
	}
	return txRxes, nil
}
