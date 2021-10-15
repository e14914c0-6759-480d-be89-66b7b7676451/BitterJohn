package common

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

func Min(a, b int) int {
	if a<b{
		return a
	}
	return b
}