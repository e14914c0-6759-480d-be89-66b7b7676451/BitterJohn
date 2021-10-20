package shadowsocks

import (
	"encoding/binary"
	"fmt"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pool"
	"github.com/pkg/errors"
	"io"
	"net"
)

type MetadataType int

const (
	MetadataTypeReserved0 MetadataType = iota
	MetadataTypeIPv4
	MetadataTypeReserved2
	MetadataTypeDomain
	MetadataTypeIPv6
	// MetadataTypeMsg indicates it's a message from SweetLisa.
	// [MetadataType(1)][MetadataCmd(1)]
	MetadataTypeMsg
)

type MetadataCmd uint8

const (
	MetadataCmdPing MetadataCmd = iota
	MetadataCmdSyncPassages
	MetadataCmdResponse
)

type Metadata struct {
	Type       MetadataType
	Hostname   string
	Port       uint16
	Cmd        MetadataCmd
	LenMsgBody uint32
}

var (
	ErrInvalidMetadata = errors.Errorf("invalid metadata")
)

func BytesSizeForMetadata(firstTwoByte []byte) (int, error) {
	if len(firstTwoByte) < 2 {
		return 0, fmt.Errorf("%w: too short", ErrInvalidMetadata)
	}
	switch MetadataType(firstTwoByte[0]) {
	case MetadataTypeIPv4:
		return 1 + 4 + 2, nil
	case MetadataTypeIPv6:
		return 1 + 16 + 2, nil
	case MetadataTypeDomain:
		lenDN := int(firstTwoByte[1])
		return 1 + 1 + lenDN + 2, nil
	case MetadataTypeMsg:
		return 1 + 1 + 4, nil
	default:
		return 0, fmt.Errorf("%w: invalid type: %v", ErrInvalidMetadata, firstTwoByte[1])
	}
}

func NewMetadata(bytesMetadata []byte) (*Metadata, error) {
	if len(bytesMetadata) < 2 {
		return nil, io.ErrUnexpectedEOF
	}
	meta := new(Metadata)
	meta.Type = MetadataType(bytesMetadata[0])
	length, err := BytesSizeForMetadata(bytesMetadata)
	if err != nil {
		return nil, err
	}
	if len(bytesMetadata) < length {
		return nil, fmt.Errorf("%w: too short", ErrInvalidMetadata)
	}
	switch meta.Type {
	case MetadataTypeIPv4:
		meta.Hostname = net.IP(bytesMetadata[1:5]).String()
		meta.Port = binary.BigEndian.Uint16(bytesMetadata[5:])
		return meta, nil
	case MetadataTypeIPv6:
		meta.Hostname = net.IP(bytesMetadata[1:17]).String()
		meta.Port = binary.BigEndian.Uint16(bytesMetadata[17:])
		return meta, nil
	case MetadataTypeDomain:
		lenDN := int(bytesMetadata[1])
		meta.Hostname = string(bytesMetadata[2 : 2+lenDN])
		meta.Port = binary.BigEndian.Uint16(bytesMetadata[2+lenDN:])
		return meta, nil
	case MetadataTypeMsg:
		meta.Cmd = MetadataCmd(bytesMetadata[1])
		meta.LenMsgBody = binary.BigEndian.Uint32(bytesMetadata[2:])
		return meta, nil
	default:
		return nil, fmt.Errorf("%w: invalid type: %v", ErrInvalidMetadata, meta.Type)
	}
}

func (meta *Metadata) Bytes() (b []byte) {
	poolBytes := meta.BytesFromPool()
	b = make([]byte, len(poolBytes))
	copy(b, poolBytes)
	pool.Put(poolBytes)
	return b
}
func (meta *Metadata) BytesFromPool() (b []byte) {
	switch meta.Type {
	case MetadataTypeIPv4:
		b = pool.Get(1 + 4 + 2)
		copy(b[1:], net.ParseIP(meta.Hostname).To4()[:4])
		binary.BigEndian.PutUint16(b[5:], meta.Port)
	case MetadataTypeIPv6:
		b = pool.Get(1 + 16 + 2)
		copy(b[1:], net.ParseIP(meta.Hostname)[:16])
		binary.BigEndian.PutUint16(b[17:], meta.Port)
	case MetadataTypeDomain:
		hostname := []byte(meta.Hostname)
		lenDN := len(hostname)
		b = pool.Get(1 + 1 + lenDN + 2)
		b[1] = uint8(lenDN)
		copy(b[2:], hostname)
		binary.BigEndian.PutUint16(b[2+lenDN:], meta.Port)
	case MetadataTypeMsg:
		b = pool.Get(1 + 1 + 4)
		b[1] = uint8(meta.Cmd)
		binary.BigEndian.PutUint32(b[2:], meta.LenMsgBody)
	}
	b[0] = uint8(meta.Type)
	return b
}
