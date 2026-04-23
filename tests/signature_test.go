package tests

import (
	"testing"

	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/curve"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/ecdsa"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/privatekey"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/signature"
)

func TestDerConversion(t *testing.T) {
	privateKey := privatekey.New(curve.Secp256k1)
	message := "This is a text message"

	signature1 := ecdsa.Sign(message, &privateKey)

	der := signature1.ToDer()
	signature2 := signature.FromDer(der)

	if signature1.R.Cmp(&signature2.R) != 0 || signature1.S.Cmp(&signature2.S) != 0 {
		t.Fatal("TestDerConversion failed")
	}
}

func TestBase64Conversion(t *testing.T) {
	privateKey := privatekey.New(curve.Secp256k1)
	message := "This is a text message"

	signature1 := ecdsa.Sign(message, &privateKey)

	base64 := signature1.ToBase64()
	signature2 := signature.FromBase64(base64)

	if signature1.R.Cmp(&signature2.R) != 0 || signature1.S.Cmp(&signature2.S) != 0 {
		t.Fatal("TestBase64Conversion failed")
	}
}

func TestUniqueness(t *testing.T) {
	privateKey := privatekey.New(curve.Secp256k1)
	message := "This is a text message"

	signature1 := ecdsa.Sign(message, &privateKey)
	signature2 := ecdsa.Sign(message, &privateKey)

	base641 := signature1.ToBase64()
	base642 := signature2.ToBase64()

	if base641 == base642 {
		t.Fatal("Same message and key produced identical signatures (expected hedged RFC 6979 to produce different signatures)")
	}
}
