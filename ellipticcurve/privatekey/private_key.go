package privatekey

import (
	"fmt"
	"math/big"

	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/curve"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/math"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/publickey"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/utils"
)

type PrivateKey struct {
	Curve  curve.CurveFp
	Secret *big.Int
}

func New(curve curve.CurveFp, secret ...*big.Int) PrivateKey {
	if len(secret) > 0 {
		privateKey := PrivateKey{
			Curve:  curve,
			Secret: secret[0],
		}
		return privateKey
	}

	return PrivateKey{
		Curve:  curve,
		Secret: utils.Between(big.NewInt(1), new(big.Int).Sub(curve.N, big.NewInt(1))),
	}
}

func (obj PrivateKey) PublicKey() publickey.PublicKey {
	publicPoint := math.Multiply(
		obj.Curve.G,
		obj.Secret,
		obj.Curve.N,
		obj.Curve.A,
		obj.Curve.P,
	)
	return publickey.PublicKey{
		Point: publicPoint,
		Curve: obj.Curve,
	}
}

func (obj PrivateKey) ToString() string {
	return utils.HexFromInt(obj.Secret)
}

func (obj PrivateKey) ToDer() []byte {
	publicKeyString := obj.PublicKey().ToString(true)
	hexadecimal := utils.EncodeConstructed(
		utils.EncodePrimitive(utils.Integer, big.NewInt(1)),
		utils.EncodePrimitive(utils.OctetString, utils.HexFromInt(obj.Secret)),
		utils.EncodePrimitive(utils.OidContainer, utils.EncodePrimitive(utils.Object, obj.Curve.Oid)),
		utils.EncodePrimitive(utils.PublicKeyPointContainer, utils.EncodePrimitive(utils.BitString, publicKeyString)),
	)
	return utils.ByteStringFromHex(hexadecimal)
}

func (obj PrivateKey) ToPem() string {
	der := obj.ToDer()
	return utils.CreatePem(utils.Base64FromByteString(der), toPemTemplate)
}

func FromPem(pem string) PrivateKey {
	privateKeyPem := utils.GetPemContent(pem, fromPemTemplate)
	return FromDer(utils.ByteStringFromBase64(privateKeyPem))
}

func FromDer(data []byte) PrivateKey {
	hexadecimal := utils.HexFromByteString(data)
	parsed := utils.Parse(hexadecimal)[0].([]interface{})
	privateKeyFlag := parsed[0].(*big.Int)
	secretHex := parsed[1].(string)
	curveOid := parsed[2].([]interface{})[0].([]int64)
	publicKeyString := parsed[3].([]interface{})[0].(string)

	if privateKeyFlag.Cmp(big.NewInt(1)) != 0 {
		panic(fmt.Sprintf(
			"Private keys should start with a '1' flag, but a '%v' was found instead",
			privateKeyFlag,
		))
	}

	curve := curve.CurveByOid(curveOid)
	privateKey := FromString(secretHex, curve)

	if privateKey.PublicKey().ToString(true) != publicKeyString {
		panic("The public key described inside the private key file doesn't match the actual public key of the pair")
	}

	return privateKey
}

func FromString(str string, curve curve.CurveFp) PrivateKey {
	return New(curve, utils.IntFromHex(str))
}

const toPemTemplate = `
-----BEGIN EC PRIVATE KEY-----
{content}
-----END EC PRIVATE KEY-----
`

const fromPemTemplate = `
^\s*(?:(?:-----BEGIN EC PARAMETERS-----)
(?:.*)
(?:-----END EC PARAMETERS-----))?
\s*-----BEGIN EC PRIVATE KEY-----
{content}
-----END EC PRIVATE KEY-----\s*
`
