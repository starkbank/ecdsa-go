package tests

import (
	"github.com/starkbank/ecdsa-go/ellipticcurve/ecdsa"
	"github.com/starkbank/ecdsa-go/ellipticcurve/privatekey"
	"github.com/starkbank/ecdsa-go/ellipticcurve/publickey"
	"github.com/starkbank/ecdsa-go/ellipticcurve/signature"
	"github.com/starkbank/ecdsa-go/ellipticcurve/utils"
	"testing"
)

func TestAssign(t *testing.T) {
	// Generated by: openssl ecparam -name secp256k1 -genkey -out privateKey.pem
	privateKeyPem := utils.File{}.Read("privatekey.pem")

	privateKey := privatekey.FromPem(string(privateKeyPem))

	message := utils.File{}.Read("message.txt")

	signature := ecdsa.Sign(string(message), &privateKey)

	publicKey := privateKey.PublicKey()

	if !ecdsa.Verify(string(message), signature, &publicKey) {
		t.Fatal("testAssign returned false")
	}
}

func TestVerifySignature(t *testing.T) {
	// openssl ec -in privateKey.pem -pubout -out publicKey.pem

	publicKeyPem := utils.File{}.Read("publickey.pem")

	// openssl dgst -sha256 -sign privateKey.pem -out signature.binary message.txt
	signatureDer := utils.File{}.Read("signatureDer.txt")

	message := utils.File{}.Read("message.txt")

	publicKey := publickey.FromPem(string(publicKeyPem))

	signature := signature.FromDer(signatureDer)

	if !ecdsa.Verify(string(message), signature, &publicKey) {
		t.Fatal("TestVerifySignature returned false")
	}
}