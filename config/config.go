package config

type Lisa struct {
	Host string `json:"host" required:"" desc:"The host of SweetLisa" json:""`
	//ValidateToken string `json:"validateToken" required:"" desc:"The CDN token to validate whether SweetLisa can know user's IP"`
}

type John struct {
	Listen string `json:"listen,omitempty" default:"0.0.0.0:8880" desc:"Address to listen on"`
	Log    Log    `json:"log,omitempty"`

	Name      string `json:"name" required:"" desc:"Server name to register"`
	Hostnames string `json:"hostname" required:"" desc:"Server hostnames for users to connect (split by \",\")"`
	Port      int    `json:"port,omitempty" default:"{{with $arr := split \":\" .john.listen}}{{$arr._1}}{{end}}" desc:"Server port for users to connect"`
	Ticket    string `json:"ticket" required:"" desc:"Ticket from SweetLisa"`
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
