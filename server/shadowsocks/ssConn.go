package shadowsocks

import (
	"crypto/cipher"
	"crypto/rand"
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
	"net"
	"sync"
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

func NewSSConn(conn net.Conn, conf CipherConf, masterKey []byte) (crw *SSConn, err error) {
	if conf.NewCipher == nil {
		return nil, fmt.Errorf("invalid CipherConf")
	}
	return &SSConn{
		Conn:       conn,
		cipherConf: conf,
		masterKey:  masterKey,
		nonceRead:  make([]byte, conf.NonceLen),
		nonceWrite: make([]byte, conf.NonceLen),
	}, nil
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
	c.onceWrite.Do(func() {
		var salt = pool.Get(c.cipherConf.SaltLen)
		defer pool.Put(salt)
		_, err = rand.Read(salt)
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
		c.cipherWrite, err = c.cipherConf.NewCipher(subKey)

		c.Conn.Write(salt)
	})
	if c.cipherWrite == nil {
		return 0, fmt.Errorf("%w: %v", ErrFailInitCihper, err)
	}
	encLen := pool.Get(2 + c.cipherConf.TagLen)
	encText := pool.Get(len(b) + c.cipherConf.TagLen)
	defer pool.Put(encLen)
	defer pool.Put(encText)
	for i := 0; i < len(b); i += 65536 {
		// write chunk
		var l = common.Min(i+65536, len(b)) - i
		binary.BigEndian.PutUint16(encLen, uint16(l))
		_ = c.cipherWrite.Seal(encLen[:0], c.nonceWrite, encLen[:2], nil)
		nn, err := c.Conn.Write(encLen)
		if err != nil {
			return 0, err
		}
		n += nn
		common.BytesIncLittleEndian(c.nonceWrite)
		_ = c.cipherWrite.Seal(encText[:0], c.nonceWrite, b[i:i+l], nil)
		nn, err = c.Conn.Write(encText[:l+c.cipherConf.TagLen])
		if err != nil {
			return 0, err
		}
		common.BytesIncLittleEndian(c.nonceWrite)
		n += nn
	}
	return len(b), err
}

func ShadowUDP(key Key, b []byte) (shadowBytes []byte, err error) {
	var buf = pool.Get(key.CipherConf.SaltLen + len(b) + key.CipherConf.TagLen) // delay putting back
	_, err = rand.Read(buf[:key.CipherConf.SaltLen])
	if err != nil {
		return
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
		return
	}
	ciph, err := key.CipherConf.NewCipher(subKey)
	if err != nil {
		return
	}
	_ = ciph.Seal(buf[key.CipherConf.SaltLen:key.CipherConf.SaltLen], ZeroNonce[:key.CipherConf.NonceLen], b, nil)
	return buf, nil
}

func (c *SSConn) ReadMetadata() (metadata *Metadata, err error) {
	var firstTwoBytes = pool.Get(2)
	_, err = io.ReadFull(c, firstTwoBytes)
	n, err := BytesSizeForMetadata(firstTwoBytes)
	if err != nil {
		return nil, err
	}
	var bytesMetadata = pool.Get(n)
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

func CalcPaddingLen(masterKey []byte, reqBody []byte, req bool) (length int) {
	maxPadding := common.Max(int(10*float64(len(reqBody))/(1+math.Log(float64(len(reqBody)))))-len(reqBody), 0)
	var h hash.Hash32
	if req {
		h = fnv.New32a()
	} else {
		h = fnv.New32()
	}
	h.Write(masterKey)
	h.Write(reqBody)
	return int(h.Sum32()) % maxPadding
}

// GetTurn executes one msg request and get one response like HTTP
func (c *SSConn) GetTurn(addr Metadata, reqBody []byte) (resp []byte, err error) {
	go func() {
		addr.Type = MetadataTypeMsg
		lenPadding := CalcPaddingLen(c.masterKey, reqBody, true)
		addr.LenMsgBody = uint32(len(reqBody))
		c.Write(addr.Bytes())
		c.Write(reqBody)
		padding := pool.Get(lenPadding)
		defer pool.Put(padding)
		c.Write(padding)
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
	padding := pool.Get(lenPadding)
	defer pool.Put(padding)
	if _, err := io.ReadFull(c, padding); err != nil {
		return nil, fmt.Errorf("%w: padding length is shorter than it should be", ErrFailAuth)
	}
	return resp, nil
}
