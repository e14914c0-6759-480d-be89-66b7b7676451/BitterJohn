package common

import (
	"reflect"
)

const Alphabet = "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM0123456789"

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
	return vFrom.Interface(), vToAdd.Interface()
}
