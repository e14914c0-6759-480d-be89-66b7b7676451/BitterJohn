package shadowsocks

import (
	"encoding/binary"
	"fmt"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pool"
	"github.com/pkg/errors"
	"io"
	"net"
)

type SocksType int

const (
	SocksTypeReserved0 SocksType = iota
	SocksTypeIPv4
	SocksTypeReserved2
	SocksTypeDomain
	SocksTypeIPv6
	SocksTypeMsg // A message from SweetLisa
)

type SocksAddr struct {
	Type     SocksType
	Hostname string
	Port     uint16
}

var (
	ErrInvalidAddress = errors.Errorf("invalid address")
)

func BytesSizeForSocksAddr(firstTwoByte []byte) (int, error) {
	if len(firstTwoByte) < 2 {
		return 0, fmt.Errorf("%w: too short", ErrInvalidAddress)
	}
	switch SocksType(firstTwoByte[0]) {
	case SocksTypeIPv4:
		return 1 + 4 + 2, nil
	case SocksTypeIPv6:
		return 1 + 16 + 2, nil
	case SocksTypeDomain:
		lenDN := int(firstTwoByte[1])
		return 1 + 1 + lenDN + 2, nil
	case SocksTypeMsg:
		// TODO:
		return 0, nil
	default:
		return 0, fmt.Errorf("%w: invalid type: %v", ErrInvalidAddress, firstTwoByte[1])
	}
}

func NewSocksAddr(bytesAddr []byte) (*SocksAddr, error) {
	if len(bytesAddr) < 2 {
		return nil, io.ErrUnexpectedEOF
	}
	addr := new(SocksAddr)
	addr.Type = SocksType(bytesAddr[0])
	length, err := BytesSizeForSocksAddr(bytesAddr)
	if err != nil {
		return nil, err
	}
	if len(bytesAddr) < length {
		return nil, fmt.Errorf("%w: too short", ErrInvalidAddress)
	}
	switch addr.Type {
	case SocksTypeIPv4:
		addr.Hostname = net.IP(bytesAddr[1:5]).String()
		addr.Port = binary.BigEndian.Uint16(bytesAddr[5:])
		return addr, nil
	case SocksTypeIPv6:
		addr.Hostname = net.IP(bytesAddr[1:17]).String()
		addr.Port = binary.BigEndian.Uint16(bytesAddr[17:])
		return addr, nil
	case SocksTypeDomain:
		lenDN := int(bytesAddr[1])
		addr.Hostname = string(bytesAddr[2 : 2+lenDN])
		addr.Port = binary.BigEndian.Uint16(bytesAddr[2+lenDN:])
		return addr, nil
	case SocksTypeMsg:
		// TODO:
		return addr, nil
	default:
		return nil, fmt.Errorf("%w: invalid type: %v", ErrInvalidAddress, addr.Type)
	}
}

func (addr *SocksAddr) Bytes() (b []byte) {
	poolBytes := addr.BytesFromPool()
	b = make([]byte, len(poolBytes))
	copy(b, poolBytes)
	pool.Put(poolBytes)
	return b
}
func (addr *SocksAddr) BytesFromPool() (b []byte) {
	switch addr.Type {
	case SocksTypeIPv4:
		b = pool.Get(1 + 4 + 2)
		copy(b[1:], net.ParseIP(addr.Hostname).To4()[:4])
		binary.BigEndian.PutUint16(b[5:], addr.Port)
	case SocksTypeIPv6:
		b = pool.Get(1 + 16 + 2)
		copy(b[1:], net.ParseIP(addr.Hostname)[:16])
		binary.BigEndian.PutUint16(b[17:], addr.Port)
	case SocksTypeDomain:
		hostname := []byte(addr.Hostname)
		lenDN := len(hostname)
		b = pool.Get(1 + 1 + lenDN + 2)
		b[1] = uint8(lenDN)
		copy(b[2:], hostname)
		binary.BigEndian.PutUint16(b[2+lenDN:], addr.Port)
	case SocksTypeMsg:
		// TODO:
	}
	b[0] = uint8(addr.Type)
	return b
}
