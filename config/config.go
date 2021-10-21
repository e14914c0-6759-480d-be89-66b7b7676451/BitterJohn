package config

type Lisa struct {
	Host          string `mapstructure:"host" required:"" desc:"The host of SweetLisa" json:",omitempty"`
	ValidateToken string `mapstructure:"validateToken" required:"" desc:"The CDN token to validate whether SweetLisa can know user's IP" json:",omitempty"`
}

type John struct {
	Listen string `mapstructure:"listen" default:"0.0.0.0:8880" desc:"Address to listen on" json:",omitempty"`
	Log    Log    `mapstructure:"log" json:",omitempty"`

	Name     string `mapstructure:"name" required:"" desc:"Server name to register" json:",omitempty"`
	Hostname string `mapstructure:"hostname" required:"" desc:"Server hostname for users to connect" json:",omitempty"`
	Port     int    `mapstructure:"port" default:"{{with $arr := split \":\" .john.listen}}{{$arr._1}}{{end}}" desc:"Server port for users to connect" json:",omitempty"`
	Ticket   string `mapstructure:"ticket" required:"" desc:"Ticket from SweetLisa" json:",omitempty"`
}

type Log struct {
	Level            string `mapstructure:"level" default:"warn" desc:"Optional values: trace, debug, info, warn or error" json:",omitempty"`
	File             string `mapstructure:"file" desc:"The path of log file" json:",omitempty"`
	MaxDays          int64  `mapstructure:"maxDays" default:"3" desc:"Maximum number of days to keep log files" json:",omitempty"`
	DisableColor     bool   `mapstructure:"disableColor" json:",omitempty"`
	DisableTimestamp bool   `mapstructure:"disableTimestamp" json:",omitempty"`
}

type Params struct {
	Lisa Lisa `mapstructure:"lisa"`
	John John `mapstructure:"john"`
}

var ParamsObj Params
