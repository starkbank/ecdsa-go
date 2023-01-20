package publickey

import (
	"fmt"
	"math/big"

	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/curve"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/math"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/point"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/utils"
)

type PublicKey struct {
	Point point.Point
	Curve curve.CurveFp
}

func (obj PublicKey) ToString(encoded bool) string {
	baseLength := 2 * obj.Curve.Length()
	stringTemplate := fmt.Sprint("%0", baseLength, "s")
	xHex := fmt.Sprintf(stringTemplate, utils.HexFromInt(obj.Point.X))
	yHex := fmt.Sprintf(stringTemplate, utils.HexFromInt(obj.Point.Y))
	str := fmt.Sprint(xHex, yHex)
	if encoded {
		return fmt.Sprint("0004", str)
	}
	return str
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
	curve := curve.CurveByOid(curveOid)
	return FromString(pointString, curve, true)
}

func FromString(str string, curve curve.CurveFp, validatePoint bool) PublicKey {
	baseLength := 2 * curve.Length()
	if len(str) > 2*baseLength && str[:4] == "0004" {
		str = str[4:]
	}

	xs := str[:baseLength]
	ys := str[baseLength:]

	publicPoint := point.Point{X: utils.IntFromHex(xs), Y: utils.IntFromHex(ys), Z: big.NewInt(0)}

	publicKey := PublicKey{
		Point: publicPoint,
		Curve: curve,
	}

	if !validatePoint {
		return publicKey
	}
	if publicPoint.IsAtInfinity() {
		panic("Public Key point is at infinity")
	}
	if !curve.Contains(publicPoint) {
		panic(fmt.Sprintf(
			"Point (%v,%v) is not valid for curve %v",
			publicPoint.X,
			publicPoint.Y,
			curve.Name,
		))
	}
	if !math.Multiply(publicPoint, curve.N, curve.N, curve.A, curve.P).IsAtInfinity() {
		panic(fmt.Sprintf(
			"Point (%v,%v) * %v.N is not at infinity",
			publicPoint.X,
			publicPoint.Y,
			curve.Name,
		))
	}
	return publicKey
}

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
