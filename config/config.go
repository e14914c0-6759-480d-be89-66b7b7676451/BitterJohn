package config

type Lisa struct {
	Host string `json:"host" required:"" desc:"The host of SweetLisa" json:""`
	//ValidateToken string `json:"validateToken" required:"" desc:"The CDN token to validate whether SweetLisa can know user's IP"`
}

type John struct {
	Listen   string `json:"listen,omitempty" default:"0.0.0.0:8880" desc:"Address to listen on"`
	Log      Log    `json:"log,omitempty"`
	Protocol string `json:"protocol,omitempty" default:"vmess"`

	Name     string `json:"name" required:"" desc:"Server name to register"`
	Hostname string `json:"hostname" required:"" desc:"Server hostnames for users to connect (split by \",\")"`
	Port     int    `json:"port,omitempty" default:"{{with $arr := split \":\" .john.listen}}{{$arr._1}}{{end}}" desc:"Server port for users to connect"`
	Ticket   string `json:"ticket" required:"" desc:"Ticket from SweetLisa"`

	BandwidthLimit BandwidthLimit `json:"bandwidthLimit"`
	NoRelay        bool           `json:"noRelay"`

	MaxDrainN int64 `json:"maxDrainN" default:"-1" desc:"Max number of bytes to drain. default value is -1, which means unlimited."`

	DoNotValidateCDN bool `json:"doNotValidateCDN" desc:"Do not validate the CDN configuration of the peer SweetLisa"`
}

type BandwidthLimit struct {
	Enable           bool  `json:"enable" default:"false"`
	ResetDay         uint8 `json:"resetDay,omitempty" desc:"ResetDay is the day of every month to reset the limit of bandwidth. Zero means never reset."`
	UplinkLimitGiB   int64 `json:"uplinkLimitGiB,omitempty" desc:"UplinkLimitGiB is the limit of uplink bandwidth in GiB. Zero means no limit."`
	DownlinkLimitGiB int64 `json:"downlinkLimitGiB,omitempty" desc:"DownlinkLimitGiB is the limit of downlink bandwidth in GiB Zero means no limit."`
	TotalLimitGiB    int64 `json:"totalLimitGiB,omitempty" desc:"TotalLimitGiB is the limit of downlink plus uplink bandwidth in GiB Zero means no limit."`
}

type Log struct {
	Level            string `json:"level,omitempty" default:"warn" desc:"Optional values: trace, debug, info, warn or error"`
	File             string `json:"file,omitempty" desc:"The path of log file"`
	MaxDays          int64  `json:"maxDays,omitempty" default:"3" desc:"Maximum number of days to keep log files"`
	DisableColor     bool   `json:"disableColor,omitempty"`
	DisableTimestamp bool   `json:"disableTimestamp,omitempty"`
}

type Params struct {
	Lisa Lisa `json:"lisa"`
	John John `json:"john"`
}

var ParamsObj Params
