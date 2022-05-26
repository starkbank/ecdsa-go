package utils

import (
	"math/big"
)

type Oid struct{}

func OidFromHex(hexadecimal string) []int64 {
	firstByte, remainingBytes := hexadecimal[:2], hexadecimal[2:]
	firstByteInt := IntFromHex(firstByte)
	oid := []int64{int64(firstByteInt.Uint64() / 40), int64(firstByteInt.Uint64() % 40)}
	oidInt := int64(0)
	for len(remainingBytes) > 0 {
		bt := remainingBytes[0:2]
		remainingBytes = remainingBytes[2:]
		byteInt := int64(IntFromHex(bt).Uint64())
		if byteInt >= 128 {
			oidInt = byteInt - 128
			continue
		}
		oidInt = oidInt*128 + byteInt
		oid = append(oid, oidInt)
		oidInt = int64(0)
	}
	return oid
}

func OidToHex(oid []int64) string {
	hexadecimal := HexFromInt(big.NewInt(40*oid[0] + oid[1]))
	for _, oidInt := range oid[2:] {
		hexadecimal += _oidNumberToHex(oidInt)
	}
	return hexadecimal
}

func _oidNumberToHex(number int64) string {
	hexadecimal := *new(string)
	endDelta := int64(0)
	for number > 0 {
		hexadecimal = HexFromInt(big.NewInt((number%int64(128))+endDelta)) + hexadecimal
		number /= 128
		endDelta = 128
	}
	if len(hexadecimal) > 0 {
		return hexadecimal
	}
	return "00"
}
