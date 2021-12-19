package common

import (
	crand "crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"math"
	"math/big"
	"math/rand"
	"net"
	"os/user"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

const Alphabet = "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM0123456789"

func BytesIncBigEndian(b []byte) {
	for i := len(b) - 1; i >= 0; i-- {
		b[i]++
		if b[i] != 0 {
			break
		}
	}
}

func BytesIncLittleEndian(b []byte) {
	for i := 0; i < len(b); i++ {
		b[i]++
		if b[i] != 0 {
			break
		}
	}
}

func Abs64(a int64) int64 {
	if a < 0 {
		return -a
	}
	return a
}

func Min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func Max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Change returns how to change "from" slice to "to" slice by removing and adding elements.
// Elements from "from" and "to" should be unique.
func Change(from interface{}, to interface{}, keyFunc func(elem interface{}) string) (toRemove interface{}, toAdd interface{}) {
	var m = make(map[string]struct{})
	var vFrom = reflect.ValueOf(from)
	var vTo = reflect.ValueOf(to)
	for i := 0; i < vTo.Len(); i++ {
		key := keyFunc(vTo.Index(i).Interface())
		m[key] = struct{}{}
	}
	var vToRemove = reflect.MakeSlice(vTo.Type(), 0, 0)
	for i := 0; i < vFrom.Len(); i++ {
		key := keyFunc(vFrom.Index(i).Interface())
		if _, ok := m[key]; !ok {
			vToRemove = reflect.Append(vToRemove, vFrom.Index(i))
		}
	}
	var vToAdd = reflect.MakeSlice(vTo.Type(), 0, 0)
	for i := 0; i < vFrom.Len(); i++ {
		key := keyFunc(vFrom.Index(i).Interface())
		if _, ok := m[key]; ok {
			delete(m, key)
		}
	}
	for i := 0; i < vTo.Len(); i++ {
		key := keyFunc(vTo.Index(i).Interface())
		if _, ok := m[key]; ok {
			vToAdd = reflect.Append(vToAdd, vTo.Index(i))
		}
	}
	return vToRemove.Interface(), vToAdd.Interface()
}

func MustMapKeys(m interface{}) (keys []string) {
	v := reflect.ValueOf(m)
	vKeys := v.MapKeys()
	for _, k := range vKeys {
		keys = append(keys, k.String())
	}
	return keys
}

func Deduplicate(list []string) []string {
	res := make([]string, 0, len(list))
	m := make(map[string]struct{})
	for _, v := range list {
		if _, ok := m[v]; ok {
			continue
		}
		m[v] = struct{}{}
		res = append(res, v)
	}
	return res
}

func HomeExpand(path string) (string, error) {
	if !strings.HasPrefix(path, "~") {
		return path, nil
	}

	usr, err := user.Current()
	if err != nil {
		return "", err
	}
	return filepath.Join(usr.HomeDir, path[1:]), nil
}

func ToIPNets(cidr []string) (nets []*net.IPNet, err error) {
	for _, c := range cidr {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return nil, err
		}
		nets = append(nets, n)
	}
	return nets, nil
}

func StarMatch(expr string, str string) bool {
	ok, err := regexp.MatchString(strings.ReplaceAll(regexp.QuoteMeta(expr), "\\*", ".*"), str)
	if err != nil {
		return false
	}
	return ok
}

func SeedSecurely() (err error) {
	n, err := crand.Int(crand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return err
	}
	rand.Seed(n.Int64())
	return nil
}

func ShouldParseInt64(a string) int64 {
	i, _ := strconv.ParseInt(a, 10, 64)
	return i
}

func ShouldParseUint8(a string) uint8 {
	i, _ := strconv.ParseUint(a, 10, 8)
	return uint8(i)
}
// StringToUUID5 is from https://github.com/XTLS/Xray-core/issues/158
func StringToUUID5(str string) string {
	var Nil [16]byte
	h := sha1.New()
	h.Write(Nil[:])
	h.Write([]byte(str))
	u := h.Sum(nil)[:16]
	u[6] = (u[6] & 0x0f) | (5 << 4)
	u[8] = u[8]&(0xff>>2) | (0x02 << 6)
	buf := make([]byte, 36)
	hex.Encode(buf[0:8], u[0:4])
	buf[8] = '-'
	hex.Encode(buf[9:13], u[4:6])
	buf[13] = '-'
	hex.Encode(buf[14:18], u[6:8])
	buf[18] = '-'
	hex.Encode(buf[19:23], u[8:10])
	buf[23] = '-'
	hex.Encode(buf[24:], u[10:])
	return string(buf)
}
