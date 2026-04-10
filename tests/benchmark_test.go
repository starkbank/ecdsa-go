package tests

import (
	"testing"

	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/curve"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/ecdsa"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/privatekey"
)

func BenchmarkSign(b *testing.B) {
	pk := privatekey.New(curve.Secp256k1)
	message := "This is a benchmark test message"

	// Warmup
	ecdsa.Sign(message, &pk)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ecdsa.Sign(message, &pk)
	}
}

func BenchmarkVerify(b *testing.B) {
	pk := privatekey.New(curve.Secp256k1)
	pub := pk.PublicKey()
	message := "This is a benchmark test message"

	sig := ecdsa.Sign(message, &pk)

	// Warmup
	ecdsa.Verify(message, sig, &pub)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ecdsa.Verify(message, sig, &pub)
	}
}
