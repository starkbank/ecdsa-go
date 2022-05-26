package utils

import (
	"crypto/rand"
	"math/big"
)

func Between(min *big.Int, max *big.Int) *big.Int {
	max = new(big.Int).Sub(max, min)
	random, _ := rand.Int(rand.Reader, max)
	return new(big.Int).Add(random, min)
}
