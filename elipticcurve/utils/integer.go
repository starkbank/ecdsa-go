package utils

import (
	"math/big"
	"crypto/rand"
)

type RandomInteger interface {
	Between(min *big.Int, max *big.Int) *big.Int
}

type Random struct {}

func (self Random) Between(min *big.Int, max *big.Int) *big.Int {
	max = new(big.Int).Sub(max, min)
	random,_ := rand.Int(rand.Reader, max)
	return new(big.Int).Add(random, min)
}
