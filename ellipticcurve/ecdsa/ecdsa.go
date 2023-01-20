package ecdsa

import (
	"crypto/sha256"
	"math/big"

	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/math"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/privatekey"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/publickey"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/signature"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/utils"
)

func Sign(message string, privateKey *privatekey.PrivateKey) signature.Signature {
	hashfunc := sha256.New()
	hashfunc.Write([]byte(message))
	byteMessage := hashfunc.Sum(nil)
	numberMessage := utils.NumberFromByteString(byteMessage)
	curve := privateKey.Curve

	zero, one := big.NewInt(0), big.NewInt(1)
	r, s := big.NewInt(0), big.NewInt(0)
	for r.Cmp(zero) == 0 && s.Cmp(zero) == 0 {
		randNum := utils.Between(one, new(big.Int).Sub(curve.N, one))
		randSignPoint := math.Multiply(curve.G, randNum, curve.N, curve.A, curve.P)
		r.Mod(randSignPoint.X, curve.N)
		s.Mul(r, privateKey.Secret)
		s.Add(s, numberMessage)
		s.Mul(s, math.Inv(randNum, curve.N))
		s.Mod(s, curve.N)
	}

	return signature.New(*r, *s)
}

func Verify(message string, Signature signature.Signature, publicKey *publickey.PublicKey) bool {
	hashfunc := sha256.New()
	hashfunc.Write([]byte(message))
	byteMessage := hashfunc.Sum(nil)
	numberMessage := utils.NumberFromByteString(byteMessage)
	curve := publicKey.Curve
	r := &Signature.R
	s := &Signature.S

	one := big.NewInt(1)
	max := big.NewInt(0).Sub(curve.N, one)
	if r.Cmp(one) < 0 || r.Cmp(max) > 0 {
		return false
	}
	if s.Cmp(one) < 0 || s.Cmp(max) > 0 {
		return false
	}

	inv := math.Inv(s, curve.N)

	nu1 := new(big.Int).Mul(numberMessage, inv)
	nu1.Mod(nu1, curve.N)
	u1 := math.Multiply(curve.G, nu1, curve.N, curve.A, curve.P)

	nu2 := new(big.Int).Mul(r, inv)
	nu2.Mod(nu2, curve.N)
	u2 := math.Multiply(publicKey.Point, nu2, curve.N, curve.A, curve.P)
	v := math.Add(u1, u2, curve.A, curve.P)
	if v.IsAtInfinity() {
		return false
	}
	return new(big.Int).Mod(v.X, curve.N).Cmp(r) == 0
}
