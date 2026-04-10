package tests

import (
	"testing"

	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/curve"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/ecdsa"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/privatekey"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/publickey"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/signature"
)

func TestSupportedCurve(t *testing.T) {
	newCurve := curve.New(
		"secp256k1",
		"0x0000000000000000000000000000000000000000000000000000000000000000",
		"0x0000000000000000000000000000000000000000000000000000000000000007",
		"0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
		"0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
		"0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
		"0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
		[]int64{1, 3, 132, 0, 10},
		"",
	)
	privateKey1 := privatekey.New(newCurve)
	publicKey1 := privateKey1.PublicKey()

	privateKeyPem := privateKey1.ToPem()
	publicKeyPem := publicKey1.ToPem()

	privateKey2 := privatekey.FromPem(privateKeyPem)
	publicKey2 := publickey.FromPem(publicKeyPem)

	message := "test"

	signatureBase64 := ecdsa.Sign(message, &privateKey2).ToBase64()
	sig := signature.FromBase64(signatureBase64)

	if !ecdsa.Verify(message, sig, &publicKey2) {
		t.Fatal("TestSupportedCurve returned false")
	}
}

func TestAddNewCurve(t *testing.T) {
	newCurve := curve.New(
		"frp256v1",
		"0xf1fd178c0b3ad58f10126de8ce42435b3961adbcabc8ca6de8fcf353d86e9c00",
		"0xee353fca5428a9300d4aba754a44c00fdfec0c9ae4b1a1803075ed967b7bb73f",
		"0xf1fd178c0b3ad58f10126de8ce42435b3961adbcabc8ca6de8fcf353d86e9c03",
		"0xf1fd178c0b3ad58f10126de8ce42435b53dc67e140d2bf941ffdd459c6d655e1",
		"0xb6b3d4c356c139eb31183d4749d423958c27d2dcaf98b70164c97a2dd98f5cff",
		"0x6142e0f7c8b204911f9271f0f3ecef8c2701c307e8e4c9e183115a1554062cfb",
		[]int64{1, 2, 250, 1, 223, 101, 256, 1},
		"",
	)
	curve.Add(newCurve)

	privateKey1 := privatekey.New(newCurve)
	publicKey1 := privateKey1.PublicKey()

	privateKeyPem := privateKey1.ToPem()
	publicKeyPem := publicKey1.ToPem()

	privateKey2 := privatekey.FromPem(privateKeyPem)
	publicKey2 := publickey.FromPem(publicKeyPem)

	message := "test"

	signatureBase64 := ecdsa.Sign(message, &privateKey2).ToBase64()
	sig := signature.FromBase64(signatureBase64)

	if !ecdsa.Verify(message, sig, &publicKey2) {
		t.Fatal("TestAddNewCurve returned false")
	}
}

func TestUnsupportedCurve(t *testing.T) {
	newCurve := curve.New(
		"brainpoolP256t1",
		"0xa9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5374",
		"0x662c61c430d84ea4fe66a7733d0b76b7bf93ebc4af2f49256ae58101fee92b04",
		"0xa9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377",
		"0xa9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7",
		"0xa3e8eb3cc1cfe7b7732213b23a656149afa142c47aafbc2b79a191562e1305f4",
		"0x2d996c823439c56d7f7b22e14644417e69bcb6de39d027001dabe8f35b25c9be",
		[]int64{1, 3, 36, 3, 3, 2, 8, 1, 1, 8},
		"",
	)

	privateKeyPem := privatekey.New(newCurve).ToPem()
	publicKeyPem := privatekey.New(newCurve).PublicKey().ToPem()

	assertPanics(t, "PrivateKey.fromPem with unsupported curve", func() {
		privatekey.FromPem(privateKeyPem)
	})

	assertPanics(t, "PublicKey.fromPem with unsupported curve", func() {
		publickey.FromPem(publicKeyPem)
	})
}
