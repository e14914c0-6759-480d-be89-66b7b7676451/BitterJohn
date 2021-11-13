package vmess

import (
	"encoding/binary"
	"fmt"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server"
	"github.com/pkg/errors"
	"net"
)

type MetadataType int

const (
	MetadataTypeReserved0 MetadataType = iota
	MetadataTypeIPv4
	MetadataTypeDomain
	MetadataTypeIPv6
	// MetadataTypeMsg indicates it's a message from SweetLisa.
	// [MetadataType(1)][MetadataCmd(1)]
	MetadataTypeMsg
)

type InstructionCmd uint8

const (
	InstructionCmdReserved0 InstructionCmd = iota
	InstructionCmdTCP
	InstructionCmdUDP
	InstructionCmdInvalid
)

type Metadata struct {
	Type     MetadataType
	Hostname string
	Port     uint16
	Cmd      server.MetadataCmd
	InsCmd   InstructionCmd
	Cipher   Cipher

	IsClient bool

	authedCmdKey  [16]byte
	authedEAuthID [16]byte
}

var (
	ErrInvalidMetadata = errors.Errorf("invalid metadata")
)

func (m *Metadata) AddrLen() int {
	switch m.Type {
	case MetadataTypeIPv4:
		return 4
	case MetadataTypeIPv6:
		return 16
	case MetadataTypeDomain:
		return 1 + len(m.Hostname)
	case MetadataTypeMsg:
		return 1
	default:
		return 0
	}
}

func (m *Metadata) PutAddr(dst []byte) (n int) {
	switch m.Type {
	case MetadataTypeIPv4:
		copy(dst, net.ParseIP(m.Hostname).To4()[:4])
		return 4
	case MetadataTypeIPv6:
		copy(dst[1:], net.ParseIP(m.Hostname)[:16])
		return 16
	case MetadataTypeDomain:
		dst[0] = byte(len([]byte(m.Hostname)))
		copy(dst[1:], m.Hostname)
		return 1 + len(m.Hostname)
	case MetadataTypeMsg:
		dst[0] = byte(m.Cmd)
		return 1
	default:
		return 0
	}
}

func (m *Metadata) CompleteFromInstructionData(instructionData []byte) (err error) {
	m.Type = MetadataType(instructionData[40])
	switch m.Type {
	case MetadataTypeIPv4:
		m.Hostname = net.IP(instructionData[41:45]).String()
	case MetadataTypeIPv6:
		m.Hostname = net.IP(instructionData[41:57]).String()
	case MetadataTypeDomain:
		m.Hostname = string(instructionData[42 : 42+instructionData[41]])
	case MetadataTypeMsg:
		m.Cmd = server.MetadataCmd(instructionData[41])
	default:
		return fmt.Errorf("NewMetadata: %w: invalid type: %v", ErrInvalidMetadata, m.Type)
	}
	m.Port = binary.BigEndian.Uint16(instructionData[38:])
	m.InsCmd = InstructionCmd(instructionData[37])
	cipher, err := NewCipherFromSecurity(instructionData[35] & 0xf)
	if err != nil {
		return err
	}
	m.Cipher = cipher
	return nil
}
