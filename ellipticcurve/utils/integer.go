package utils

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"math/big"
)

func Between(min *big.Int, max *big.Int) *big.Int {
	diff := new(big.Int).Sub(max, min)
	diff.Add(diff, big.NewInt(1))
	random, _ := rand.Int(rand.Reader, diff)
	return new(big.Int).Add(random, min)
}

// HashFunc represents a hash function constructor
type HashFunc func() hash.Hash

// Sha256 returns a new SHA-256 hash
func Sha256() hash.Hash {
	return sha256.New()
}

// Sha512 returns a new SHA-512 hash
func Sha512() hash.Hash {
	return sha512.New()
}

// Rfc6979 generates nonce values per hedged RFC 6979: deterministic k derivation
// with fresh random entropy mixed into K-init (RFC 6979 §3.6). Same message and
// key yield different signatures, while preserving RFC 6979's protection against
// RNG failures.
// Returns a closure that yields *big.Int nonce candidates.
func Rfc6979(hashBytes []byte, secret *big.Int, N *big.Int, orderBitLen int, hashfunc HashFunc) func() *big.Int {
	orderByteLen := (orderBitLen + 7) / 8

	secretHex := HexFromInt(secret)
	for len(secretHex) < orderByteLen*2 {
		secretHex = "0" + secretHex
	}
	secretBytes := ByteStringFromHex(secretHex)

	hashReduced := new(big.Int).Set(NumberFromByteString(hashBytes, orderBitLen))
	hashReduced.Mod(hashReduced, N)
	hashHex := HexFromInt(hashReduced)
	for len(hashHex) < orderByteLen*2 {
		hashHex = "0" + hashHex
	}
	hashOctets := ByteStringFromHex(hashHex)

	extraEntropy := make([]byte, orderByteLen)
	if _, err := rand.Read(extraEntropy); err != nil {
		panic(err)
	}

	hLen := hashfunc().Size()
	V := make([]byte, hLen)
	for i := range V {
		V[i] = 0x01
	}
	K := make([]byte, hLen)

	// K = HMAC(K, V || 0x00 || secret || hash || extraEntropy)
	mac := hmac.New(hashfunc, K)
	mac.Write(V)
	mac.Write([]byte{0x00})
	mac.Write(secretBytes)
	mac.Write(hashOctets)
	mac.Write(extraEntropy)
	K = mac.Sum(nil)

	// V = HMAC(K, V)
	mac = hmac.New(hashfunc, K)
	mac.Write(V)
	V = mac.Sum(nil)

	// K = HMAC(K, V || 0x01 || secret || hash || extraEntropy)
	mac = hmac.New(hashfunc, K)
	mac.Write(V)
	mac.Write([]byte{0x01})
	mac.Write(secretBytes)
	mac.Write(hashOctets)
	mac.Write(extraEntropy)
	K = mac.Sum(nil)

	// V = HMAC(K, V)
	mac = hmac.New(hashfunc, K)
	mac.Write(V)
	V = mac.Sum(nil)

	nMinus1 := new(big.Int).Sub(N, big.NewInt(1))

	return func() *big.Int {
		for {
			T := make([]byte, 0)
			for len(T)*8 < orderBitLen {
				mac = hmac.New(hashfunc, K)
				mac.Write(V)
				V = mac.Sum(nil)
				T = append(T, V...)
			}

			k := NumberFromByteString(T, orderBitLen)

			if k.Cmp(big.NewInt(1)) >= 0 && k.Cmp(nMinus1) <= 0 {
				return k
			}

			// K = HMAC(K, V || 0x00)
			mac = hmac.New(hashfunc, K)
			mac.Write(V)
			mac.Write([]byte{0x00})
			K = mac.Sum(nil)

			// V = HMAC(K, V)
			mac = hmac.New(hashfunc, K)
			mac.Write(V)
			V = mac.Sum(nil)
		}
	}
}
