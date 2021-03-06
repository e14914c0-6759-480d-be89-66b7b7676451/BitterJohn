package common

import (
	"bytes"
	"testing"
)

func TestBytesAddBigEndian(t *testing.T) {
	tt := [][2][]byte{
		{{0, 0, 0}, {0, 0, 1}},
		{{0, 0, 255}, {0, 1, 0}},
		{{0, 255, 255}, {1, 0, 0}},
		{{255, 255, 255}, {0, 0, 0}},
		{{55, 255, 255}, {56, 0, 0}},
		{{56, 23, 255}, {56, 24, 0}},
		{{56, 24, 22}, {56, 24, 23}},
	}
	for i, test := range tt {
		BytesIncBigEndian(test[0])
		if !bytes.Equal(test[0], test[1]) {
			t.Fatal(i, test[0], "!=", test[1])
		}
	}
}

func TestBytesAddLittleEndian(t *testing.T) {
	tt := [][2][]byte{
		{{0, 0, 0}, {1, 0, 0}},
		{{255, 0, 0}, {0, 1, 0}},
		{{255, 255, 0}, {0, 0, 1}},
		{{255, 255, 255}, {0, 0, 0}},
		{{255, 255, 55}, {0, 0, 56}},
		{{255, 23, 56}, {0, 24, 56}},
		{{22, 24, 56}, {23, 24, 56}},
	}
	for i, test := range tt {
		BytesIncLittleEndian(test[0])
		if !bytes.Equal(test[0], test[1]) {
			t.Fatal(i, test[0], "!=", test[1])
		}
	}
}

func TestStarMatch(t *testing.T) {
	tt := [][3]interface{}{
		{"test.com", "test.com", true},
		{"test*.com", "test.com", true},
		{"test*.com", "testcom", false},
		{"test*.com", "test.example.com", true},
		{"*test.com", "test.example.com", false},
		{"*test.com", "1test.com", true},
		{"t*test.com", "testetest.com", true},
		{`*`, `test.com`, true},
	}
	for _, test := range tt {
		if StarMatch(test[0].(string), test[1].(string)) != test[2].(bool) {
			t.Fatal(test)
		}
	}
}
