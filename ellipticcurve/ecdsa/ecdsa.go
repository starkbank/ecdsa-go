package ecdsa

import (
	"math/big"

	ecmath "github.com/starkbank/ecdsa-go/v2/ellipticcurve/math"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/privatekey"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/publickey"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/signature"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/utils"
)

func Sign(message string, privateKey *privatekey.PrivateKey, hashfunc ...utils.HashFunc) signature.Signature {
	hf := utils.HashFunc(utils.Sha256)
	if len(hashfunc) > 0 {
		hf = hashfunc[0]
	}

	h := hf()
	h.Write([]byte(message))
	byteMessage := h.Sum(nil)

	curve := privateKey.Curve
	numberMessage := utils.NumberFromByteString(byteMessage, curve.NBitLength)

	zero := big.NewInt(0)
	r := big.NewInt(0)
	s := big.NewInt(0)
	var randSignPoint_X, randSignPoint_Y *big.Int

	genParams := ecmath.MultiplyGeneratorParams{
		G:          curve.G,
		A:          curve.A,
		P:          curve.P,
		N:          curve.N,
		NBitLength: curve.NBitLength,
		Cache:      curve.GeneratorCache,
	}
	nextK := utils.Rfc6979(byteMessage, privateKey.Secret, curve.N, curve.NBitLength, hf)
	for r.Cmp(zero) == 0 || s.Cmp(zero) == 0 {
		randNum := nextK()
		randSignPoint := ecmath.MultiplyGenerator(genParams, randNum)
		randSignPoint_X = randSignPoint.X
		randSignPoint_Y = randSignPoint.Y
		r = new(big.Int).Mod(randSignPoint.X, curve.N)
		// s = (numberMessage + r * secret) * inv(randNum, N) mod N
		s = new(big.Int).Mul(r, privateKey.Secret)
		s.Add(s, numberMessage)
		s.Mul(s, ecmath.Inv(randNum, curve.N))
		s.Mod(s, curve.N)
	}

	// Recovery ID
	recoveryId := int(new(big.Int).And(randSignPoint_Y, big.NewInt(1)).Int64())
	if randSignPoint_X.Cmp(curve.N) > 0 {
		recoveryId += 2
	}

	// Low-S normalization
	halfN := new(big.Int).Div(curve.N, big.NewInt(2))
	if s.Cmp(halfN) > 0 {
		s = new(big.Int).Sub(curve.N, s)
		recoveryId ^= 1
	}

	return signature.New(*r, *s, recoveryId)
}

func Verify(message string, sig signature.Signature, publicKey *publickey.PublicKey, hashfunc ...utils.HashFunc) bool {
	hf := utils.HashFunc(utils.Sha256)
	if len(hashfunc) > 0 {
		hf = hashfunc[0]
	}

	h := hf()
	h.Write([]byte(message))
	byteMessage := h.Sum(nil)

	curve := publicKey.Curve
	numberMessage := utils.NumberFromByteString(byteMessage, curve.NBitLength)
	r := &sig.R
	s := &sig.S

	one := big.NewInt(1)
	nMinus1 := new(big.Int).Sub(curve.N, one)
	if r.Cmp(one) < 0 || r.Cmp(nMinus1) > 0 {
		return false
	}
	if s.Cmp(one) < 0 || s.Cmp(nMinus1) > 0 {
		return false
	}

	// Public key on-curve validation
	if !curve.Contains(publicKey.Point) {
		return false
	}

	inv := ecmath.Inv(s, curve.N)

	// Shamir's trick for verification
	u1 := new(big.Int).Mul(numberMessage, inv)
	u1.Mod(u1, curve.N)
	u2 := new(big.Int).Mul(r, inv)
	u2.Mod(u2, curve.N)

	v := ecmath.MultiplyAndAdd(curve.G, u1, publicKey.Point, u2, curve.N, curve.A, curve.P)
	if v.IsAtInfinity() {
		return false
	}
	return new(big.Int).Mod(v.X, curve.N).Cmp(r) == 0
}
