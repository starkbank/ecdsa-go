package publickey

import (
	"fmt"
	"math/big"

	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/curve"
	ecmath "github.com/starkbank/ecdsa-go/v2/ellipticcurve/math"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/point"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/utils"
)

type PublicKey struct {
	Point point.Point
	Curve curve.CurveFp
}

func (obj PublicKey) ToString(encoded bool) string {
	baseLength := 2 * obj.Curve.Length()
	xHex := fmt.Sprintf("%0*s", baseLength, utils.HexFromInt(obj.Point.X))
	yHex := fmt.Sprintf("%0*s", baseLength, utils.HexFromInt(obj.Point.Y))
	str := xHex + yHex
	if encoded {
		return "0004" + str
	}
	return str
}

func (obj PublicKey) ToCompressed() string {
	baseLength := 2 * obj.Curve.Length()
	parityTag := _evenTag
	if new(big.Int).Mod(obj.Point.Y, big.NewInt(2)).Cmp(big.NewInt(0)) != 0 {
		parityTag = _oddTag
	}
	xHex := fmt.Sprintf("%0*s", baseLength, utils.HexFromInt(obj.Point.X))
	return parityTag + xHex
}

func (obj PublicKey) ToDer() []byte {
	hexadecimal := utils.EncodeConstructed(
		utils.EncodeConstructed(
			utils.EncodePrimitive(utils.Object, _ecdsaPublicKeyOid),
			utils.EncodePrimitive(utils.Object, obj.Curve.Oid),
		),
		utils.EncodePrimitive(utils.BitString, obj.ToString(true)),
	)
	return utils.ByteStringFromHex(hexadecimal)
}

func (obj PublicKey) ToPem() string {
	der := obj.ToDer()
	return utils.CreatePem(utils.Base64FromByteString(der), toPemTemplate)
}

func FromPem(pem string) PublicKey {
	publicKeyPem := utils.GetPemContent(pem, fromPemTemplate)
	return FromDer(utils.ByteStringFromBase64(publicKeyPem))
}

func FromDer(data []byte) PublicKey {
	hexadecimal := utils.HexFromByteString(data)
	parsed := utils.Parse(hexadecimal)[0].([]interface{})
	curveData := parsed[0]
	pointString := parsed[1].(string)
	publicKeyOid := curveData.([]interface{})[0].([]int64)
	curveOid := curveData.([]interface{})[1].([]int64)

	if !curve.IsOidEqual(publicKeyOid, _ecdsaPublicKeyOid) {
		panic(fmt.Sprintf(
			"The Public Key Object Identifier (OID) should be %v, but %v was found instead",
			_ecdsaPublicKeyOid,
			publicKeyOid,
		))
	}
	c := curve.GetByOid(curveOid)
	return FromString(pointString, c, true)
}

func FromString(str string, c curve.CurveFp, validatePoint bool) PublicKey {
	baseLength := 2 * c.Length()
	if len(str) > 2*baseLength && str[:4] == "0004" {
		str = str[4:]
	}

	xs := str[:baseLength]
	ys := str[baseLength:]

	publicPoint := point.Point{X: utils.IntFromHex(xs), Y: utils.IntFromHex(ys), Z: big.NewInt(0)}

	publicKey := PublicKey{
		Point: publicPoint,
		Curve: c,
	}

	if !validatePoint {
		return publicKey
	}
	if publicPoint.IsAtInfinity() {
		panic("Public Key point is at infinity")
	}
	if !c.Contains(publicPoint) {
		panic(fmt.Sprintf(
			"Point (%v,%v) is not valid for curve %v",
			publicPoint.X,
			publicPoint.Y,
			c.Name,
		))
	}
	if !ecmath.Multiply(publicPoint, c.N, c.N, c.A, c.P).IsAtInfinity() {
		panic(fmt.Sprintf(
			"Point (%v,%v) * %v.N is not at infinity",
			publicPoint.X,
			publicPoint.Y,
			c.Name,
		))
	}
	return publicKey
}

func FromCompressed(str string, c ...curve.CurveFp) PublicKey {
	curv := curve.Secp256k1
	if len(c) > 0 {
		curv = c[0]
	}

	parityTag := str[:2]
	xHex := str[2:]
	if parityTag != _evenTag && parityTag != _oddTag {
		panic("Compressed string should start with 02 or 03")
	}
	x := utils.IntFromHex(xHex)
	y := curv.Y(x, parityTag == _evenTag)
	return PublicKey{
		Point: point.Point{X: x, Y: y, Z: big.NewInt(0)},
		Curve: curv,
	}
}

const _evenTag = "02"
const _oddTag = "03"

var _ecdsaPublicKeyOid = []int64{1, 2, 840, 10045, 2, 1}

const toPemTemplate = `
-----BEGIN PUBLIC KEY-----
{content}
-----END PUBLIC KEY-----
`

const fromPemTemplate = `
^\s*-----BEGIN PUBLIC KEY-----
{content}
-----END PUBLIC KEY-----\s*$
`
