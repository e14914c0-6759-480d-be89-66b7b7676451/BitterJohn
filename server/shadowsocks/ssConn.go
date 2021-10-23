package shadowsocks

import (
	"crypto/cipher"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/common"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/log"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pool"
	"golang.org/x/crypto/hkdf"
	"hash"
	"hash/fnv"
	"io"
	"math"
	"math/rand"
	"net"
	"sync"
)

const (
	TCPChunkMaxLen = (1 << (16 - 2)) - 1
)

var (
	ErrFailAuth       = fmt.Errorf("fail to authenticate")
	ErrFailInitCihper = fmt.Errorf("fail to initiate cipher")
)

type SSConn struct {
	net.Conn
	cipherConf CipherConf
	masterKey  []byte

	cipherRead  cipher.AEAD
	cipherWrite cipher.AEAD
	onceRead    sync.Once
	onceWrite   sync.Once
	nonceRead   []byte
	nonceWrite  []byte

	// mutex protect leftToRead and indexToRead
	mutex       sync.Mutex
	leftToRead  []byte
	indexToRead int
}

type Key struct {
	CipherConf CipherConf
	MasterKey  []byte
}

func EncryptedPayloadLen(plainTextLen int, tagLen int) int {
	n := plainTextLen / TCPChunkMaxLen
	if plainTextLen%TCPChunkMaxLen > 0 {
		n++
	}
	return plainTextLen + n*(2+tagLen+tagLen)
}

func NewSSConn(conn net.Conn, conf CipherConf, masterKey []byte) (crw *SSConn, err error) {
	if conf.NewCipher == nil {
		return nil, fmt.Errorf("invalid CipherConf")
	}
	return &SSConn{
		Conn:       conn,
		cipherConf: conf,
		masterKey:  masterKey,
		nonceRead:  pool.GetZero(conf.NonceLen),
		nonceWrite: pool.GetZero(conf.NonceLen),
	}, nil
}

func (c *SSConn) Close() error {
	pool.Put(c.nonceWrite)
	pool.Put(c.nonceRead)
	return c.Conn.Close()
}

func (c *SSConn) Read(b []byte) (n int, err error) {
	c.onceRead.Do(func() {
		var salt = pool.Get(c.cipherConf.SaltLen)
		defer pool.Put(salt)
		n, err = io.ReadFull(c.Conn, salt)
		if err != nil {
			return
		}
		subKey := pool.Get(c.cipherConf.KeyLen)
		defer pool.Put(subKey)
		kdf := hkdf.New(
			sha1.New,
			c.masterKey,
			salt,
			ReusedInfo,
		)
		_, err = io.ReadFull(kdf, subKey)
		if err != nil {
			return
		}
		c.cipherRead, err = c.cipherConf.NewCipher(subKey)
	})
	if c.cipherRead == nil {
		return 0, fmt.Errorf("%w: %v", ErrFailInitCihper, err)
	}
	c.mutex.Lock()
	if c.indexToRead < len(c.leftToRead)-1 {
		n = copy(b, c.leftToRead[c.indexToRead:])
		c.indexToRead += n
		if c.indexToRead == len(c.leftToRead)-1 {
			// Put the buf back
			pool.Put(c.leftToRead)
		}
		c.mutex.Unlock()
		return n, nil
	}
	c.mutex.Unlock()
	// Chunk
	chunk, err := c.readChunk()
	if err != nil {
		return 0, err
	}
	n = copy(b, chunk)
	if n < len(chunk) {
		// Wait for the next read
		c.mutex.Lock()
		c.leftToRead = chunk
		c.indexToRead = n
		c.mutex.Unlock()
	} else {
		// Full reading. Put the buf back
		pool.Put(chunk)
	}
	return n, nil
}

func (c *SSConn) readChunk() ([]byte, error) {
	bufLen := pool.Get(2 + c.cipherConf.TagLen)
	defer pool.Put(bufLen)
	if _, err := io.ReadFull(c.Conn, bufLen); err != nil {
		return nil, err
	}
	bLenPayload, err := c.cipherRead.Open(bufLen[:0], c.nonceRead, bufLen, nil)
	if err != nil {
		log.Warn("%v: %v", ErrFailAuth, err)
		return nil, ErrFailAuth
	}
	common.BytesIncLittleEndian(c.nonceRead)
	lenPayload := binary.BigEndian.Uint16(bLenPayload)
	bufPayload := pool.Get(int(lenPayload) + c.cipherConf.TagLen) // delay putting back
	if _, err = io.ReadFull(c.Conn, bufPayload); err != nil {
		return nil, err
	}
	payload, err := c.cipherRead.Open(bufPayload[:0], c.nonceRead, bufPayload, nil)
	if err != nil {
		log.Warn("%v: %v", ErrFailAuth, err)
		return nil, ErrFailAuth
	}
	common.BytesIncLittleEndian(c.nonceRead)
	return payload, nil
}

func (c *SSConn) Write(b []byte) (n int, err error) {
	var buf []byte
	var offset int
	c.onceWrite.Do(func() {
		buf = pool.Get(c.cipherConf.SaltLen + EncryptedPayloadLen(len(b), c.cipherConf.TagLen))
		_, err = rand.Read(buf[:c.cipherConf.SaltLen])
		if err != nil {
			pool.Put(buf)
			return
		}
		subKey := pool.Get(c.cipherConf.KeyLen)
		defer pool.Put(subKey)
		kdf := hkdf.New(
			sha1.New,
			c.masterKey,
			buf[:c.cipherConf.SaltLen],
			ReusedInfo,
		)
		_, err = io.ReadFull(kdf, subKey)
		if err != nil {
			pool.Put(buf)
			return
		}
		c.cipherWrite, err = c.cipherConf.NewCipher(subKey)
		offset += c.cipherConf.SaltLen
	})
	if buf == nil {
		buf = pool.Get(EncryptedPayloadLen(len(b), c.cipherConf.TagLen))
	}
	defer pool.Put(buf)
	if c.cipherWrite == nil {
		return 0, fmt.Errorf("%w: %v", ErrFailInitCihper, err)
	}
	for i := 0; i < len(b); i += TCPChunkMaxLen {
		// write chunk
		var l = common.Min(TCPChunkMaxLen, len(b)-i)
		binary.BigEndian.PutUint16(buf[offset:], uint16(l))
		_ = c.cipherWrite.Seal(buf[offset:offset], c.nonceWrite, buf[offset:offset+2], nil)
		offset += 2 + c.cipherConf.TagLen
		common.BytesIncLittleEndian(c.nonceWrite)

		_ = c.cipherWrite.Seal(buf[offset:offset], c.nonceWrite, b[i:i+l], nil)
		offset += l + c.cipherConf.TagLen
		common.BytesIncLittleEndian(c.nonceWrite)
	}
	_, err = c.Conn.Write(buf)
	if err != nil {
		return 0, err
	}
	return len(b), err
}

// EncryptUDPFromPool returns shadowBytes from pool.
// the shadowBytes MUST be put back.
func EncryptUDPFromPool(key Key, b []byte) (shadowBytes []byte, err error) {
	var buf = pool.Get(key.CipherConf.SaltLen + len(b) + key.CipherConf.TagLen)
	defer func() {
		if err != nil {
			pool.Put(buf)
		}
	}()
	_, err = rand.Read(buf[:key.CipherConf.SaltLen])
	if err != nil {
		return nil, err
	}
	subKey := pool.Get(key.CipherConf.KeyLen)
	defer pool.Put(subKey)
	kdf := hkdf.New(
		sha1.New,
		key.MasterKey,
		buf[:key.CipherConf.SaltLen],
		ReusedInfo,
	)
	_, err = io.ReadFull(kdf, subKey)
	if err != nil {
		return nil, err
	}
	ciph, err := key.CipherConf.NewCipher(subKey)
	if err != nil {
		return nil, err
	}
	_ = ciph.Seal(buf[key.CipherConf.SaltLen:key.CipherConf.SaltLen], ZeroNonce[:key.CipherConf.NonceLen], b, nil)
	return buf, nil
}

// DecryptUDP will decrypt the data in place
func DecryptUDP(key Key, shadowBytes []byte) (plainText []byte, err error) {
	subKey := pool.Get(key.CipherConf.KeyLen)
	defer pool.Put(subKey)
	kdf := hkdf.New(
		sha1.New,
		key.MasterKey,
		shadowBytes[:key.CipherConf.SaltLen],
		ReusedInfo,
	)
	_, err = io.ReadFull(kdf, subKey)
	if err != nil {
		return
	}
	ciph, err := key.CipherConf.NewCipher(subKey)
	if err != nil {
		return
	}
	plainText, err = ciph.Open(shadowBytes[key.CipherConf.SaltLen:key.CipherConf.SaltLen], ZeroNonce[:key.CipherConf.NonceLen], shadowBytes[key.CipherConf.SaltLen:], nil)
	if err != nil {
		return nil, err
	}
	copy(shadowBytes, plainText)
	return shadowBytes[:len(plainText)], nil
}

func (c *SSConn) ReadMetadata() (metadata *Metadata, err error) {
	var firstTwoBytes = pool.Get(2)
	defer pool.Put(firstTwoBytes)
	if _, err = io.ReadFull(c, firstTwoBytes); err != nil {
		return nil, err
	}
	n, err := BytesSizeForMetadata(firstTwoBytes)
	if err != nil {
		return nil, err
	}
	var bytesMetadata = pool.Get(n)
	defer pool.Put(bytesMetadata)
	copy(bytesMetadata, firstTwoBytes)
	_, err = io.ReadFull(c, bytesMetadata[2:])
	if err != nil {
		return nil, err
	}
	metadata, err = NewMetadata(bytesMetadata)
	if err != nil {
		return nil, err
	}
	return metadata, nil
}

func CalcPaddingLen(masterKey []byte, bodyWithoutAddr []byte, req bool) (length int) {
	maxPadding := common.Max(int(10*float64(len(bodyWithoutAddr))/(1+math.Log(float64(len(bodyWithoutAddr)))))-len(bodyWithoutAddr), 0)
	if maxPadding == 0 {
		return 0
	}
	var h hash.Hash32
	if req {
		h = fnv.New32a()
	} else {
		h = fnv.New32()
	}
	h.Write(masterKey)
	h.Write(bodyWithoutAddr)
	return int(h.Sum32()) % maxPadding
}

// GetTurn executes one msg request and get one response like HTTP
func (c *SSConn) GetTurn(addr Metadata, reqBody []byte) (resp []byte, err error) {
	go func() {
		addr.Type = MetadataTypeMsg
		lenPadding := CalcPaddingLen(c.masterKey, reqBody, true)
		addr.LenMsgBody = uint32(len(reqBody))
		bAddr := addr.BytesFromPool()
		defer pool.Put(bAddr)
		buf := pool.Get(len(bAddr) + len(reqBody) + lenPadding)
		defer pool.Put(buf)
		copy(buf, bAddr)
		copy(buf[len(bAddr):], reqBody)
		log.Trace("GetTurn: write to %v: %v", c.RemoteAddr().String(), buf)
		c.Write(buf)
	}()
	respMeta, err := c.ReadMetadata()
	if err != nil {
		return nil, err
	}
	if respMeta.Type != MetadataTypeMsg || respMeta.Cmd != MetadataCmdResponse {
		return nil, fmt.Errorf("%w: unexpected metadata type %v or cmd %v", ErrFailAuth, respMeta.Type, respMeta.Cmd)
	}
	// we know the body length but we should read all
	resp = make([]byte, int(respMeta.LenMsgBody))
	if _, err := io.ReadFull(c, resp); err != nil {
		return nil, fmt.Errorf("%w: response body length is shorter than it should be", ErrFailAuth)
	}
	lenPadding := CalcPaddingLen(c.masterKey, resp, false)
	if lenPadding > 0 {
		padding := pool.Get(lenPadding)
		defer pool.Put(padding)
		if _, err := io.ReadFull(c, padding); err != nil {
			return nil, fmt.Errorf("%w: padding length is shorter than it should be: %v", ErrFailAuth, err)
		}
	}
	return resp, nil
}
