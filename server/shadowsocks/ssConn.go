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
	"io"
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

func NewSSConn(conn net.Conn, conf CipherConf, masterKey []byte) (crw *SSConn) {
	return &SSConn{
		Conn:       conn,
		cipherConf: conf,
		masterKey:  masterKey,
		nonceRead:  make([]byte, conf.NonceLen),
		nonceWrite: make([]byte, conf.NonceLen),
	}
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
	cipherConf := CiphersConf[key.method]
	var buf = pool.Get(cipherConf.SaltLen + len(b) + cipherConf.TagLen) // delay putting back
	_, err = rand.Read(buf[:cipherConf.SaltLen])
	if err != nil {
		return
	}
	subKey := pool.Get(cipherConf.KeyLen)
	defer pool.Put(subKey)
	kdf := hkdf.New(
		sha1.New,
		key.masterKey,
		buf[:cipherConf.SaltLen],
		ReusedInfo,
	)
	_, err = io.ReadFull(kdf, subKey)
	if err != nil {
		return
	}
	ciph, err := cipherConf.NewCipher(subKey)
	if err != nil {
		return
	}
	_ = ciph.Seal(buf[cipherConf.SaltLen:cipherConf.SaltLen], ZeroNonce[:cipherConf.NonceLen], b, nil)
	return buf, nil
}
