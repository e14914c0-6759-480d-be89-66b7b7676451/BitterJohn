package vmess

import (
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/common"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/fastrand"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/log"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pool"
	"github.com/v2fly/v2ray-core/v4/common/crypto"
	"github.com/v2fly/v2ray-core/v4/proxy/vmess/encoding"
	"io"
	"net"
	"sync"
)

type Conn struct {
	net.Conn
	initRead  sync.Once
	initWrite sync.Once
	metadata  Metadata
	cmdKey    []byte

	NewAEAD func(key []byte) (cipher.AEAD, error)

	writeBodyCipher       cipher.AEAD
	writeNonceGenerator   crypto.BytesGenerator
	writeChunkSizeParser  crypto.ChunkSizeEncoder
	writePaddingGenerator crypto.PaddingLengthGenerator

	readBodyCipher       cipher.AEAD
	readNonceGenerator   crypto.BytesGenerator
	readChunkSizeParser  crypto.ChunkSizeDecoder
	readPaddingGenerator crypto.PaddingLengthGenerator

	requestBodyKey [16]byte
	requestBodyIV  [16]byte
	requestOptions byte

	responseBodyKey [16]byte
	responseBodyIV  [16]byte
	responseAuth    byte

	mutex       sync.Mutex
	leftToRead  []byte
	indexToRead int
}

func NewConn(conn net.Conn, metadata Metadata, cmdKey []byte) (c *Conn, err error) {
	key := pool.Get(len(cmdKey))
	copy(key, cmdKey)
	return &Conn{
		Conn:     conn,
		metadata: metadata,
		cmdKey:   key,
	}, nil
}

func (c *Conn) Close() error {
	pool.Put(c.cmdKey)
	return c.Conn.Close()
}

func (c *Conn) chunks(size int) (payloadSize int, numChunks int) {
	payloadSize = 2048 - c.writeBodyCipher.Overhead() - int(c.writeChunkSizeParser.SizeBytes()) - int(c.writePaddingGenerator.MaxPaddingLen())
	if size%payloadSize == 0 {
		return payloadSize, size / payloadSize
	}
	return payloadSize, size/payloadSize + 1
}

func GenerateChunkNonce(nonce []byte, size uint32) crypto.BytesGenerator {
	c := append([]byte(nil), nonce...)
	count := uint16(0)
	return func() []byte {
		binary.BigEndian.PutUint16(c, count)
		count++
		return c[:size]
	}
}

// seal packs the b. The overhead is sizeParser.SizeBytes() + auth.Overhead() + paddingSize(no more than maxPadding).
func (c *Conn) sealFromPool(b []byte) (data []byte) {
	sizeSize := c.writeChunkSizeParser.SizeBytes()
	encryptedSize := int32(len(b) + c.writeBodyCipher.Overhead())
	paddingSize := int32(c.writePaddingGenerator.NextPaddingLen())

	data = pool.Get(int(sizeSize + encryptedSize + paddingSize))
	c.writeChunkSizeParser.Encode(uint16(encryptedSize+paddingSize), data)

	c.writeBodyCipher.Seal(data[sizeSize:sizeSize], c.writeNonceGenerator(), b, nil)
	fastrand.Read(data[len(data)-int(paddingSize):])
	//log.Warn("write: size: %v, padding: %v", encryptedSize+paddingSize, paddingSize)
	return data
}

// writeStream splits mb into multiple FIXED size (payloadSize) chunks.
// Then seal the chunks and write separately.
// If the sum size of mb less than one payloadSize, seal and write it directly.
func (c *Conn) writeStream(b []byte) (n int, err error) {
	payloadSize, numChunks := c.chunks(len(b))
	for i := 0; i < numChunks; i++ {
		data := c.sealFromPool(b[n:common.Min(n+payloadSize, len(b))])
		_, err = c.Conn.Write(data)
		if err != nil {
			pool.Put(data)
			return n, err
		}
		pool.Put(data)
		n += payloadSize
	}
	if n > len(b) {
		n = len(b)
	}
	return n, nil
}

// writePacket simply seal every buffer of mb and write.
func (c *Conn) writePacket(b []byte) (n int, err error) {
	data := c.sealFromPool(b)
	defer pool.Put(data)
	_, err = c.Conn.Write(data)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *Conn) InitContext(instructionData []byte) error {
	c.responseAuth = instructionData[33]
	copy(c.requestBodyIV[:], instructionData[1:])
	copy(c.requestBodyKey[:], instructionData[17:])
	tmp := sha256.Sum256(c.requestBodyIV[:])
	copy(c.responseBodyIV[:], tmp[:16])
	tmp = sha256.Sum256(c.requestBodyKey[:])
	copy(c.responseBodyKey[:], tmp[:16])
	if c.metadata.Cipher == "" {
		ciph, err := NewCipherFromSecurity(instructionData[35] & 0xf)
		if err != nil {
			return err
		}
		c.metadata.Cipher = ciph
	}
	newAEAD, ok := NewCipherMapper[c.metadata.Cipher]
	if !ok {
		return fmt.Errorf("unexpected cipher: %v", c.metadata.Cipher)
	}
	c.NewAEAD = newAEAD
	c.requestOptions = instructionData[34]
	return nil
}

// Write writes data to the connection. Empty b should be written before closing the connection to indicate the terminal.
func (c *Conn) Write(b []byte) (n int, err error) {
	c.initWrite.Do(func() {
		if c.metadata.IsClient {
			instructionData := ReqInstructionDataFromPool(c.metadata)
			defer pool.Put(instructionData)

			if err = c.InitContext(instructionData); err != nil {
				return
			}

			var header []byte
			if header, err = EncryptReqHeaderFromPool(instructionData, c.cmdKey); err != nil {
				pool.Put(header)
				return
			}
			defer pool.Put(header)
			if c.writeBodyCipher, err = c.NewAEAD(c.requestBodyKey[:]); err != nil {
				return
			}

			if ContainOption(c.requestOptions, OptionChunkLengthMasking) {
				c.writeChunkSizeParser = encoding.NewShakeSizeParser(c.requestBodyIV[:])
				if ContainOption(c.requestOptions, OptionGlobalPadding) {
					c.writePaddingGenerator = c.writeChunkSizeParser.(crypto.PaddingLengthGenerator)
				}
			} else {
				c.writeChunkSizeParser = crypto.PlainChunkSizeParser{}
			}
			if c.writePaddingGenerator == nil {
				c.writePaddingGenerator = PlainPaddingGenerator{}
			}
			c.writeNonceGenerator = GenerateChunkNonce(c.requestBodyIV[:], uint32(c.writeBodyCipher.NonceSize()))
			_, err = c.Conn.Write(header)
		} else {
			header := RespHeaderFromPool(c.responseAuth)
			defer pool.Put(header)
			var encHeader []byte
			encHeader, err = c.EncryptRespHeaderFromPool(header)
			if err != nil {
				return
			}
			defer pool.Put(encHeader)
			if c.writeBodyCipher, err = c.NewAEAD(c.responseBodyKey[:]); err != nil {
				return
			}
			if ContainOption(c.requestOptions, OptionChunkLengthMasking) {
				c.writeChunkSizeParser = encoding.NewShakeSizeParser(c.responseBodyIV[:])

				if ContainOption(c.requestOptions, OptionGlobalPadding) {
					c.writePaddingGenerator = c.writeChunkSizeParser.(crypto.PaddingLengthGenerator)
				}
			} else {
				c.writeChunkSizeParser = crypto.PlainChunkSizeParser{}
			}
			if c.writePaddingGenerator == nil {
				c.writePaddingGenerator = PlainPaddingGenerator{}
			}
			c.writeNonceGenerator = GenerateChunkNonce(c.responseBodyIV[:], uint32(c.writeBodyCipher.NonceSize()))
			_, err = c.Conn.Write(encHeader)
		}
	})
	if err != nil {
		return 0, err
	}
	if len(b) == 0 {
		data := c.sealFromPool(nil)
		defer pool.Put(data)
		_, err = c.Conn.Write(data)
		return 0, err
	}
	switch c.metadata.InsCmd {
	case InstructionCmdTCP:
		return c.writeStream(b)
	case InstructionCmdUDP:
		return c.writePacket(b)
	default:
		return 0, fmt.Errorf("unsupported network (instruction cmd): %v", c.metadata.InsCmd)
	}
}

func (c *Conn) Read(b []byte) (n int, err error) {
	c.initRead.Do(func() {
		if c.metadata.IsClient {
			buf := pool.Get(18) // 2+16
			defer pool.Put(buf)
			if _, err = io.ReadFull(c.Conn, buf); err != nil {
				err = fmt.Errorf("failed to read response header length: %w", err)
				return
			}
			var ciph cipher.AEAD
			if ciph, err = NewAesGcm(KDF(c.responseBodyKey[:], []byte(KDFSaltConstAEADRespHeaderLenKey))[:16]); err != nil {
				return
			}
			if _, err = ciph.Open(buf[:0], KDF(c.responseBodyIV[:], []byte(KDFSaltConstAEADRespHeaderLenIV))[:12], buf, nil); err != nil {
				return
			}
			headerSize := binary.BigEndian.Uint16(buf[:2])
			buf = pool.Get(int(headerSize) + 16)
			defer pool.Put(buf)
			if _, err = io.ReadFull(c.Conn, buf); err != nil {
				err = fmt.Errorf("failed to read response header: %w", err)
				return
			}
			if ciph, err = NewAesGcm(KDF(c.responseBodyKey[:], []byte(KDFSaltConstAEADRespHeaderPayloadKey))[:16]); err != nil {
				return
			}
			if _, err = ciph.Open(buf[:0], KDF(c.responseBodyIV[:], []byte(KDFSaltConstAEADRespHeaderPayloadIV))[:12], buf, nil); err != nil {
				return
			}
			if buf[0] != c.responseAuth {
				err = fmt.Errorf("unexpected response auth: %v, expect %v", buf[0], c.responseAuth)
				return
			}
			respCmd := buf[2]
			if respCmd != 0 {
				err = fmt.Errorf("unexpected response command: %v", respCmd)
				return
			}
			if c.readBodyCipher, err = c.NewAEAD(c.responseBodyKey[:]); err != nil {
				return
			}

			if ContainOption(c.requestOptions, OptionChunkLengthMasking) {
				c.readChunkSizeParser = encoding.NewShakeSizeParser(c.responseBodyIV[:])

				if ContainOption(c.requestOptions, OptionGlobalPadding) {
					c.readPaddingGenerator = c.readChunkSizeParser.(crypto.PaddingLengthGenerator)
				}
			} else {
				c.readChunkSizeParser = crypto.PlainChunkSizeParser{}
			}
			if c.readPaddingGenerator == nil {
				c.readPaddingGenerator = PlainPaddingGenerator{}
			}
			c.readNonceGenerator = GenerateChunkNonce(c.responseBodyIV[:], uint32(c.readBodyCipher.NonceSize()))
		} else {
			// assume that EAuthID has been read
			buf := pool.Get(26) // len(2) + tag(16) + connection_nonce(8)
			defer pool.Put(buf)
			if _, err = io.ReadFull(c.Conn, buf); err != nil {
				err = fmt.Errorf("failed to read ALength and ConnectionNonce: %w", err)
				return
			}
			connectionNonce := buf[18:26]
			c.cmdKey = c.metadata.authedCmdKey[:]
			var ciph cipher.AEAD
			if ciph, err = NewAesGcm(KDF(c.cmdKey, []byte(KDFSaltConstVMessHeaderPayloadLengthAEADKey), c.metadata.authedEAuthID[:], connectionNonce)[:16]); err != nil {
				return
			}
			if _, err = ciph.Open(buf[:0], KDF(c.cmdKey, []byte(KDFSaltConstVMessHeaderPayloadLengthAEADIV), c.metadata.authedEAuthID[:], connectionNonce)[:12], buf[:18], c.metadata.authedEAuthID[:]); err != nil {
				return
			}
			lenInstruction := binary.BigEndian.Uint16(buf)

			instructionData := pool.Get(int(lenInstruction) + 16)
			defer pool.Put(instructionData)
			if _, err = io.ReadFull(c.Conn, instructionData); err != nil {
				err = fmt.Errorf("failed to read instruction data: %w", err)
				return
			}
			if ciph, err = NewAesGcm(KDF(c.cmdKey, []byte(KDFSaltConstVMessHeaderPayloadAEADKey), c.metadata.authedEAuthID[:], connectionNonce)[:16]); err != nil {
				return
			}
			if _, err = ciph.Open(instructionData[:0], KDF(c.cmdKey, []byte(KDFSaltConstVMessHeaderPayloadAEADIV), c.metadata.authedEAuthID[:], connectionNonce)[:12], instructionData, c.metadata.authedEAuthID[:]); err != nil {
				return
			}
			if err = c.InitContext(instructionData[:lenInstruction]); err != nil {
				return
			}
			if err = c.metadata.CompleteFromInstructionData(instructionData[:lenInstruction]); err != nil {
				return
			}

			if c.readBodyCipher, err = c.NewAEAD(c.requestBodyKey[:]); err != nil {
				return
			}
			if ContainOption(c.requestOptions, OptionChunkLengthMasking) {
				c.readChunkSizeParser = encoding.NewShakeSizeParser(c.requestBodyIV[:])

				if ContainOption(c.requestOptions, OptionGlobalPadding) {
					c.readPaddingGenerator = c.readChunkSizeParser.(crypto.PaddingLengthGenerator)
				}
			} else {
				c.readChunkSizeParser = crypto.PlainChunkSizeParser{}
			}
			if c.readPaddingGenerator == nil {
				c.readPaddingGenerator = PlainPaddingGenerator{}
			}
			c.readNonceGenerator = GenerateChunkNonce(c.requestBodyIV[:], uint32(c.readBodyCipher.NonceSize()))
		}
	})
	if err != nil {
		return 0, err
	}
	if b == nil {
		return 0, nil
	}

	// dump unread data
	c.mutex.Lock()
	if c.indexToRead < len(c.leftToRead) {
		n = copy(b, c.leftToRead[c.indexToRead:])
		c.indexToRead += n
		if c.indexToRead >= len(c.leftToRead) {
			// put the buf back
			pool.Put(c.leftToRead)
		}
		c.mutex.Unlock()
		return n, nil
	}
	c.mutex.Unlock()

	chunk, err := c.readChunkFromPool()
	if err != nil {
		return 0, err
	}
	n = copy(b, chunk)
	if n < len(chunk) {
		// wait for the next read
		c.mutex.Lock()
		c.leftToRead = chunk
		c.indexToRead = n
		c.mutex.Unlock()
	} else {
		// full reading. put the buf back
		pool.Put(chunk)
	}
	return n, nil
}

func (c *Conn) Metadata() Metadata {
	return c.metadata
}

// readSize reads the size and padding from Conn. size=encryptedSize+padding
func (c *Conn) readSize() (size uint16, padding uint16, err error) {
	buf := pool.Get(int(c.readChunkSizeParser.SizeBytes()))
	defer pool.Put(buf)
	if _, err := io.ReadFull(c.Conn, buf); err != nil {
		return 0, 0, err
	}
	padding = c.readPaddingGenerator.NextPaddingLen()
	size, err = c.readChunkSizeParser.Decode(buf)
	if err != nil {
		return size, padding, err
	}
	//log.Warn("read: size: %v, padding: %v", size, padding)
	return size, padding, nil
}

func (c *Conn) readChunkFromPool() (b []byte, err error) {
	size, padding, err := c.readSize()
	if err != nil {
		return nil, err
	}
	// terminal signal
	if size == uint16(c.readBodyCipher.Overhead())+padding {
		return nil, io.EOF
	}
	b = pool.Get(int(size))
	if _, err = io.ReadFull(c.Conn, b); err != nil {
		pool.Put(b)
		return nil, err
	}
	return c.readBodyCipher.Open(b[:0], c.readNonceGenerator(), b[:len(b)-int(padding)], nil)
}

func (c *Conn) EncryptRespHeaderFromPool(header []byte) (b []byte, err error) {
	buf := pool.Get(34 + len(header)) // length(2) + tag(16) + len(header) + tag(16)

	ciph, err := NewAesGcm(KDF(c.responseBodyKey[:], []byte(KDFSaltConstAEADRespHeaderLenKey))[:16])
	if err != nil {
		return
	}
	binary.BigEndian.PutUint16(buf, uint16(len(header)))
	ciph.Seal(buf[:0], KDF(c.responseBodyIV[:], []byte(KDFSaltConstAEADRespHeaderLenIV))[:12], buf[:2], nil)

	ciph, err = NewAesGcm(KDF(c.responseBodyKey[:], []byte(KDFSaltConstAEADRespHeaderPayloadKey))[:16])
	if err != nil {
		return
	}
	ciph.Seal(buf[18:18], KDF(c.responseBodyIV[:], []byte(KDFSaltConstAEADRespHeaderPayloadIV))[:12], header, nil)

	return buf, nil
}
