package utils

import (
	b64 "encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
)

func NumberFromByteString(data []byte) *big.Int {
	ans, _ := new(big.Int).SetString(hex.EncodeToString(data), 16)
	return ans
}

func IntFromHex(hexadecimal string) *big.Int {
	bigInt, _ := new(big.Int).SetString(hexadecimal, 16)
	return bigInt
}

func HexFromInt(bigInt *big.Int) string {
	hexadecimal := fmt.Sprintf("%x", bigInt)
	if len(hexadecimal)%2 == 1 {
		hexadecimal = "0" + hexadecimal
	}
	return hexadecimal
}

func BitsFromHex(hexadecimal string) string {
	bits, _ := strconv.ParseUint(hexadecimal, 16, 32)
	stringTemplate := fmt.Sprint("%0", len(hexadecimal)*4, "b")
	return fmt.Sprintf(stringTemplate, bits)
}

func ByteStringFromBase64(base64 string) []byte {
	bytes, _ := b64.StdEncoding.DecodeString((base64))
	return bytes
}

func Base64FromByteString(byteString []byte) string {
	return b64.StdEncoding.EncodeToString(byteString)
}

func HexFromByteString(byteString []byte) string {
	return hex.EncodeToString(byteString)
}

func ByteStringFromHex(hexadecimal string) []byte {
	data, _ := hex.DecodeString(hexadecimal)
	return data
}
