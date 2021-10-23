package common

import (
	crand "crypto/rand"
	"math"
	"math/big"
	"math/rand"
	"net"
	"os/user"
	"path/filepath"
	"reflect"
	"regexp"
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
