package signature

import (
	"math/big"

	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/utils"
)

type Signature struct {
	R          big.Int
	S          big.Int
	RecoveryId int
}

func New(r big.Int, s big.Int, recoveryId ...int) Signature {
	rid := 0
	if len(recoveryId) > 0 {
		rid = recoveryId[0]
	}
	return Signature{
		R:          r,
		S:          s,
		RecoveryId: rid,
	}
}

func (obj Signature) ToDer(withRecoveryId ...bool) []byte {
	hexadecimal := obj._ToString()
	encodedSequence := utils.ByteStringFromHex(hexadecimal)
	if len(withRecoveryId) > 0 && withRecoveryId[0] {
		prefix := []byte{byte(27 + obj.RecoveryId)}
		return append(prefix, encodedSequence...)
	}
	return encodedSequence
}

func (obj Signature) ToBase64(withRecoveryId ...bool) string {
	return utils.Base64FromByteString(obj.ToDer(withRecoveryId...))
}

func FromDer(str []byte, recoveryByte ...bool) Signature {
	recByte := false
	if len(recoveryByte) > 0 {
		recByte = recoveryByte[0]
	}

	recoveryId := 0
	hasRecoveryId := false
	if recByte {
		recoveryId = int(str[0]) - 27
		hasRecoveryId = true
		str = str[1:]
	}

	hexadecimal := utils.HexFromByteString(str)
	sig := _FromString(hexadecimal)
	if hasRecoveryId {
		sig.RecoveryId = recoveryId
	}
	return sig
}

func FromBase64(str string, recoveryByte ...bool) Signature {
	der := utils.ByteStringFromBase64(str)
	return FromDer(der, recoveryByte...)
}

func (obj Signature) _ToString() string {
	return utils.EncodeConstructed(
		utils.EncodePrimitive(utils.Integer, &obj.R),
		utils.EncodePrimitive(utils.Integer, &obj.S),
	)
}

func _FromString(str string) Signature {
	parse := utils.Parse(str)[0]
	r := parse.([]interface{})[0].(*big.Int)
	s := parse.([]interface{})[1].(*big.Int)
	return New(*r, *s)
}
