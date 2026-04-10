package tests

import (
	"testing"

	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/curve"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/ecdsa"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/privatekey"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/signature"
)

func TestRecoveryIdDerConversion(t *testing.T) {
	privateKey := privatekey.New(curve.Secp256k1)
	message := "This is a text message"

	signature1 := ecdsa.Sign(message, &privateKey)

	der := signature1.ToDer(true)
	signature2 := signature.FromDer(der, true)

	if signature1.R.Cmp(&signature2.R) != 0 {
		t.Fatal("RecoveryId DER conversion: R mismatch")
	}
	if signature1.S.Cmp(&signature2.S) != 0 {
		t.Fatal("RecoveryId DER conversion: S mismatch")
	}
	if signature1.RecoveryId != signature2.RecoveryId {
		t.Fatalf("RecoveryId DER conversion: RecoveryId mismatch: got %d, expected %d",
			signature2.RecoveryId, signature1.RecoveryId)
	}
}

func TestRecoveryIdBase64Conversion(t *testing.T) {
	privateKey := privatekey.New(curve.Secp256k1)
	message := "This is a text message"

	signature1 := ecdsa.Sign(message, &privateKey)

	base64 := signature1.ToBase64(true)
	signature2 := signature.FromBase64(base64, true)

	if signature1.R.Cmp(&signature2.R) != 0 {
		t.Fatal("RecoveryId Base64 conversion: R mismatch")
	}
	if signature1.S.Cmp(&signature2.S) != 0 {
		t.Fatal("RecoveryId Base64 conversion: S mismatch")
	}
	if signature1.RecoveryId != signature2.RecoveryId {
		t.Fatalf("RecoveryId Base64 conversion: RecoveryId mismatch: got %d, expected %d",
			signature2.RecoveryId, signature1.RecoveryId)
	}
}
