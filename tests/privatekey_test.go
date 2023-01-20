package tests

import (
	"reflect"
	"testing"

	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/curve"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/privatekey"
)

func TestPrivateKeyPemConversion(t *testing.T) {
	privateKey1 := privatekey.New(curve.Secp256k1)
	pem := privateKey1.ToPem()
	privateKey2 := privatekey.FromPem(pem)

	if (privateKey1.Secret.Cmp(privateKey2.Secret)) != 0 ||
		!reflect.DeepEqual(privateKey1.Curve, privateKey2.Curve) {
		t.Fatal("TestPrivateKeyPemConversion failed")
	}
}

func TestPrivateKeyDerConversion(t *testing.T) {
	privateKey1 := privatekey.New(curve.Secp256k1)
	der := privateKey1.ToDer()
	privateKey2 := privatekey.FromDer(der)

	if (privateKey1.Secret.Cmp(privateKey2.Secret)) != 0 ||
		!reflect.DeepEqual(privateKey1.Curve, privateKey2.Curve) {
		t.Fatal("TestPrivateKeyDerConversion failed")
	}
}

func TestPrivateKeyStringConversion(t *testing.T) {
	privateKey1 := privatekey.New(curve.Secp256k1)
	keyString := privateKey1.ToString()
	privateKey2 := privatekey.FromString(keyString, curve.Secp256k1)

	if (privateKey1.Secret.Cmp(privateKey2.Secret)) != 0 ||
		!reflect.DeepEqual(privateKey1.Curve, privateKey2.Curve) {
		t.Fatal("TestPrivateKeyStringConversion failed")
	}
}
