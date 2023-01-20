package tests

import (
	"math/big"
	"testing"

	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/curve"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/ecdsa"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/privatekey"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/signature"
)

func TestVerifyRightMessage(t *testing.T) {
	privateKey := privatekey.New(curve.Secp256k1)
	publicKey := privateKey.PublicKey()

	message := "This is the right message"

	signature := ecdsa.Sign(message, &privateKey)

	if !ecdsa.Verify(message, signature, &publicKey) {
		t.Fatal("TestVerifyRightMessage returned false")
	}
}

func TestVerifyWrongMessage(t *testing.T) {
	privateKey := privatekey.New(curve.Secp256k1)
	publicKey := privateKey.PublicKey()

	message1 := "This is the right message"
	message2 := "This is the wrong message"

	signature := ecdsa.Sign(message1, &privateKey)

	if ecdsa.Verify(message2, signature, &publicKey) {
		t.Fatal("TestVerifyWrongMessage returned true")
	}
}
func TestZeroSignature(t *testing.T) {
	privateKey := privatekey.New(curve.Secp256k1)
	publicKey := privateKey.PublicKey()

	message2 := "This is the wrong message"

	zero := *big.NewInt(0)
	if ecdsa.Verify(message2, signature.New(zero, zero), &publicKey) {
		t.Fatal("testZeroSignature returned true")
	}
}
