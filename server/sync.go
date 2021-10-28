package server

import (
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/common"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/common/procfs"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/config"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/log"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/SweetLisa/model"
	"time"
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


func GeneratePingResp() (resp model.PingResp, err error) {
	now := time.Now()
	limit := config.ParamsObj.John.BandwidthLimit
	if !limit.Enable {
		return model.PingResp{}, nil
	}
	txRxes, err := procfs.InterfacesTxRx()
	if err != nil {
		return model.PingResp{}, err
	}
	var (
		maxRxKiB int64
		maxTxKib int64
	)
	for _, txRx := range txRxes {
		if txRx.RxBytes/1024 > maxRxKiB {
			maxRxKiB = txRx.RxBytes / 1024
		}
		if txRx.TxBytes/1024 > maxTxKib {
			maxTxKib = txRx.TxBytes / 1024
		}
	}
	var pingResp = model.PingResp{
		BandwidthLimit: model.BandwidthLimit{
			ResetDay:         time.Date(now.Year(), now.Month(), int(limit.ResetDay), 0, 0, 0, 0, time.Local),
			UplinkLimitGiB:   limit.UplinkLimitGiB,
			DownlinkLimitGiB: limit.DownlinkLimitGiB,
			TotalLimitGiB:    limit.TotalLimitGiB,
			UplinkKiB:        maxTxKib,
			DownlinkKiB:      maxRxKiB,
		},
	}
	return pingResp, nil
}