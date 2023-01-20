package signature

import (
	"math/big"

	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/utils"
)

type Signature struct {
	R big.Int
	S big.Int
}

func New(r big.Int, s big.Int) Signature {
	return Signature{
		R: r,
		S: s,
	}
}

func (obj Signature) ToDer() []byte {
	hexadecimal := obj._ToString()
	return utils.ByteStringFromHex(hexadecimal)
}

func (obj Signature) ToBase64() string {
	return utils.Base64FromByteString(obj.ToDer())
}

func FromDer(str []byte) Signature {
	hexadecimal := utils.HexFromByteString(str)
	return _FromString(hexadecimal)
}

func FromBase64(str string) Signature {
	der := utils.ByteStringFromBase64(str)
	return FromDer(der)
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
