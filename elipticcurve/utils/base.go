package utils

import (
	"encoding/base64"
)

type Base64er interface {
	Decode(str string) string
	Encode(str string) string
}

type Base64 struct {}

func (self Base64) Decode(str string) string {
	strDec,_ := base64.StdEncoding.DecodeString(str)
	return string(strDec)
}

func (self Base64) Encode(str string) string {
	return base64.StdEncoding.EncodeToString([]byte (str))
}
