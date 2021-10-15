package common

import (
	"io"
)

func BytesIncBigEndian(b []byte) {
	i := len(b) - 1
	for i >= 0 && b[i] == 255 {
		b[i] = 0
		i--
	}
	if i >= 0 {
		b[i]++
	}
}

func BytesIncLittleEndian(b []byte) {
	i := 0
	for i < len(b) && b[i] == 255 {
		b[i] = 0
		i++
	}
	if i < len(b) {
		b[i]++
	}
}

// MustRead reads full or drains
func MustRead(r io.Reader, buf []byte) (n int, err error) {
	n, err = io.ReadFull(r, buf)
	if err != nil {
		nn, _ := io.Copy(io.Discard, r)
		return n + int(nn), err
	}
	return n, nil
}

func Min(a, b int) int {
	if a<b{
		return a
	}
	return b
}