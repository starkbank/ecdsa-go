package tests

import (
	"testing"

	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/curve"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/privatekey"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/publickey"
)

func TestCompPubKeyBatch(t *testing.T) {
	for i := 0; i < 1000; i++ {
		privateKey := privatekey.New(curve.Secp256k1)
		pubKey := privateKey.PublicKey()
		publicKeyString := pubKey.ToCompressed()

		recoveredPublicKey := publickey.FromCompressed(publicKeyString, pubKey.Curve)

		if pubKey.Point.X.Cmp(recoveredPublicKey.Point.X) != 0 {
			t.Fatalf("TestCompPubKeyBatch: X mismatch at iteration %d", i)
		}
		if pubKey.Point.Y.Cmp(recoveredPublicKey.Point.Y) != 0 {
			t.Fatalf("TestCompPubKeyBatch: Y mismatch at iteration %d", i)
		}
	}
}

func TestFromCompressedEven(t *testing.T) {
	publicKeyCompressed := "0252972572d465d016d4c501887b8df303eee3ed602c056b1eb09260dfa0da0ab2"
	pubKey := publickey.FromCompressed(publicKeyCompressed)
	expected := "\n-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEUpclctRl0BbUxQGIe43zA+7j7WAsBWse\nsJJg36DaCrKIdC9NyX2e22/ZRrq8AC/fsG8myvEXuUBe15J1dj/bHA==\n-----END PUBLIC KEY-----\n"
	if pubKey.ToPem() != expected {
		t.Fatalf("TestFromCompressedEven: PEM mismatch\nGot:      %q\nExpected: %q", pubKey.ToPem(), expected)
	}
}

func TestFromCompressedOdd(t *testing.T) {
	publicKeyCompressed := "0318ed2e1ec629e2d3dae7be1103d4f911c24e0c80e70038f5eb5548245c475f50"
	pubKey := publickey.FromCompressed(publicKeyCompressed)
	expected := "\n-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEGO0uHsYp4tPa574RA9T5EcJODIDnADj1\n61VIJFxHX1BMIg0B4cpBnLG6SzOTthXpndIKpr8HEHj3D9lJAI50EQ==\n-----END PUBLIC KEY-----\n"
	if pubKey.ToPem() != expected {
		t.Fatalf("TestFromCompressedOdd: PEM mismatch\nGot:      %q\nExpected: %q", pubKey.ToPem(), expected)
	}
}

func TestToCompressedEven(t *testing.T) {
	pubKey := publickey.FromPem("-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEUpclctRl0BbUxQGIe43zA+7j7WAsBWse\nsJJg36DaCrKIdC9NyX2e22/ZRrq8AC/fsG8myvEXuUBe15J1dj/bHA==\n-----END PUBLIC KEY-----")
	publicKeyCompressed := pubKey.ToCompressed()
	expected := "0252972572d465d016d4c501887b8df303eee3ed602c056b1eb09260dfa0da0ab2"
	if publicKeyCompressed != expected {
		t.Fatalf("TestToCompressedEven: got %s, expected %s", publicKeyCompressed, expected)
	}
}

func TestToCompressedOdd(t *testing.T) {
	pubKey := publickey.FromPem("-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEGO0uHsYp4tPa574RA9T5EcJODIDnADj1\n61VIJFxHX1BMIg0B4cpBnLG6SzOTthXpndIKpr8HEHj3D9lJAI50EQ==\n-----END PUBLIC KEY-----")
	publicKeyCompressed := pubKey.ToCompressed()
	expected := "0318ed2e1ec629e2d3dae7be1103d4f911c24e0c80e70038f5eb5548245c475f50"
	if publicKeyCompressed != expected {
		t.Fatalf("TestToCompressedOdd: got %s, expected %s", publicKeyCompressed, expected)
	}
}
