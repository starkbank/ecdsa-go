package tests

import (
	"testing"

	"github.com/starkbank/ecdsa-go/ellipticcurve/curve"
	"github.com/starkbank/ecdsa-go/ellipticcurve/ecdsa"
	"github.com/starkbank/ecdsa-go/ellipticcurve/privatekey"
	"github.com/starkbank/ecdsa-go/ellipticcurve/publickey"
	"github.com/starkbank/ecdsa-go/ellipticcurve/signature"
)

func TestMany(t *testing.T) {
	for i := 0; i < 1000; i++ {
		privateKey1 := privatekey.New(curve.Secp256k1)
		publicKey1 := privateKey1.PublicKey()

		privateKeyPem := privateKey1.ToPem()
		publicKeyPem := publicKey1.ToPem()

		privateKey2 := privatekey.FromPem(privateKeyPem)
		publicKey2 := publickey.FromPem(publicKeyPem)

		message := "test"

		signatureBase64 := ecdsa.Sign(message, &privateKey2).ToBase64()
		signature := signature.FromBase64(signatureBase64)

		if !ecdsa.Verify(message, signature, &publicKey2) {
			t.Fatal("testMany returned false")
		}
	}
}
