package utils

import (
	"fmt"
	"math/big"
)

type DER interface {
	EncodeSequence(encodedPieces ...[]byte) []byte
	EncodeLength(length int) []byte
	EncodeInteger(r *big.Int) []byte
	EncodeNumber(n int64) []byte
	EncodeOid(pieces ...int64) []byte
	EncodeBitString(s []byte) []byte
	EncodeOctetString(s []byte) []byte
	EncodeConstructed(tag int64, value []byte) []byte
	ReadLength(str []byte) []int
	ReadNumber(str []byte)
	RemoveSequence(str []byte) []byte
	RemoveInteger(str []byte) []struct{}
	RemoveObject(str string) []struct{}
	RemoveBitString(str []byte) []byte
	RemoveOctetString(str []byte) []byte
	RemoveConstructed(str []byte) []struct{}
	FromPem(pem string) []byte
	ToPem(der []byte, name string) string
}

type Der struct{}

func (self Der) EncodeSequence(encodedPieces ...[]byte) []byte {
	totalLen := 0
	stringPieces := []byte("\x30")
	for i := 0; i < len(encodedPieces); i++ {
		p := encodedPieces[i]
		totalLen += len(p)
		pbytes := []byte(p)
		for j := 0; j< len(pbytes); j++ {
			stringPieces = append(stringPieces, pbytes[j])
		}
	}

	tail := []byte(self.EncodeLength(totalLen))
	for i := 0; i< len(tail); i++ {
		stringPieces = append(stringPieces, tail[i])
	}
	return stringPieces
}

func (self Der) EncodeLength(length int) []byte {
	if length >= 0 {
		if length < 0x80 {
			return []byte{byte(length)}
		}
	}	
	hexString := fmt.Sprintf("%x", length)
	if len(hexString) % 2 != 0 {
		hexString = "0" + hexString
	}
	s := []byte(BinaryFromHex(hexString))
	tail := []byte(fmt.Sprintf("%x", 0x80 | len(s)))
	for i := 0; i < len(tail); i++ {
		s = append(s, tail[i])
	}
	return s
}
