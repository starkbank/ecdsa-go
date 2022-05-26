package tests

import (
	"reflect"
	"testing"

	"github.com/starkbank/ecdsa-go/ellipticcurve/curve"
	"github.com/starkbank/ecdsa-go/ellipticcurve/privatekey"
	"github.com/starkbank/ecdsa-go/ellipticcurve/publickey"
)

func TestPublicKeyPemConversion(t *testing.T) {
	privateKey := privatekey.New(curve.Secp256k1)
	publicKey1 := privateKey.PublicKey()
	pem := publicKey1.ToPem()
	publicKey2 := publickey.FromPem(pem)

	if !reflect.DeepEqual(publicKey1.Point, publicKey2.Point) ||
		!reflect.DeepEqual(publicKey1.Curve, publicKey2.Curve) {
		t.Fatal("TestPublicKeyPemConversion failed")
	}
}

func TestPublicKeyDerConversion(t *testing.T) {
	privateKey := privatekey.New(curve.Secp256k1)
	publicKey1 := privateKey.PublicKey()
	der := publicKey1.ToDer()
	publicKey2 := publickey.FromDer(der)

	if !reflect.DeepEqual(publicKey1.Point, publicKey2.Point) ||
		!reflect.DeepEqual(publicKey1.Curve, publicKey2.Curve) {
		t.Fatal("TestPublicKeyDerConversion failed")
	}
}

func TestPublicKeyStringConversion(t *testing.T) {
	privateKey := privatekey.New(curve.Secp256k1)
	publicKey1 := privateKey.PublicKey()
	keyString := publicKey1.ToString(true)
	publicKey2 := publickey.FromString(keyString, curve.Secp256k1, true)

	if !reflect.DeepEqual(publicKey1.Point, publicKey2.Point) ||
		!reflect.DeepEqual(publicKey1.Curve, publicKey2.Curve) {
		t.Fatal("TestPublicKeyStringConversion failed")
	}
}
