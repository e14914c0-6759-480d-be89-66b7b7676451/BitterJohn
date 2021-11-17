package protocol

type Metadata struct {
	Type     MetadataType
	Hostname string
	Port     uint16
	// Cmd is valid only if Type is MetadataTypeMsg.
	Cmd      MetadataCmd
	Network  string
	Cipher   string
	IsClient bool
}

type MetadataCmd uint8

const (
	MetadataCmdPing MetadataCmd = iota
	MetadataCmdSyncPassages
	MetadataCmdResponse
)

type MetadataType int

const (
	MetadataTypeIPv4 MetadataType = iota
	MetadataTypeIPv6
	MetadataTypeDomain
	MetadataTypeMsg
	MetadataTypeInvalid
)
