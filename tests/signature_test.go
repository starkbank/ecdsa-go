package tests

import (
	"reflect"
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

	if !reflect.DeepEqual(signature1, signature2) {
		t.Fatal("TestDerConversion returned false")
	}
}

func TestBase64Conversion(t *testing.T) {
	privateKey := privatekey.New(curve.Secp256k1)
	message := "This is a text message"

	signature1 := ecdsa.Sign(message, &privateKey)

	base64 := signature1.ToBase64()
	signature2 := signature.FromBase64(base64)

	if !reflect.DeepEqual(signature1, signature2) {
		t.Fatal("TestDerConversion returned false")
	}
}
