package tests

import (
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/curve"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/ecdsa"
	ecmath "github.com/starkbank/ecdsa-go/v2/ellipticcurve/math"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/point"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/privatekey"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/publickey"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/signature"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/utils"
)

// ===================== Prime256v1 Public Key Derivation Tests =====================

// RFC 6979 A.2.5 public key derivation. Signatures are hedged, so r/s no longer
// match fixed test vectors, but pubkey derivation is unchanged.

func rfc6979PrivateKey() privatekey.PrivateKey {
	secret, _ := new(big.Int).SetString("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721", 16)
	return privatekey.New(curve.Prime256v1, secret)
}

func TestPublicKeyMatchesRfc(t *testing.T) {
	pk := rfc6979PrivateKey()
	pub := pk.PublicKey()

	expectedX, _ := new(big.Int).SetString("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6", 16)
	expectedY, _ := new(big.Int).SetString("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299", 16)

	if pub.Point.X.Cmp(expectedX) != 0 {
		t.Fatalf("RFC 6979 public key X mismatch")
	}
	if pub.Point.Y.Cmp(expectedY) != 0 {
		t.Fatalf("RFC 6979 public key Y mismatch")
	}
}

func TestSampleMessageRoundTrip(t *testing.T) {
	pk := rfc6979PrivateKey()
	pub := pk.PublicKey()

	sig := ecdsa.Sign("sample", &pk)

	halfN := new(big.Int).Div(curve.Prime256v1.N, big.NewInt(2))
	if sig.S.Cmp(halfN) > 0 {
		t.Fatal("prime256v1 sample signature s > N/2")
	}
	if !ecdsa.Verify("sample", sig, &pub) {
		t.Fatal("prime256v1 sample signature verification failed")
	}
}

func TestTestMessageRoundTrip(t *testing.T) {
	pk := rfc6979PrivateKey()
	pub := pk.PublicKey()

	sig := ecdsa.Sign("test", &pk)

	halfN := new(big.Int).Div(curve.Prime256v1.N, big.NewInt(2))
	if sig.S.Cmp(halfN) > 0 {
		t.Fatal("prime256v1 test signature s > N/2")
	}
	if !ecdsa.Verify("test", sig, &pub) {
		t.Fatal("prime256v1 test signature verification failed")
	}
}

// ===================== Secp256k1 Public Key Derivation Tests =====================

func secp256k1Secret1Key() privatekey.PrivateKey {
	return privatekey.New(curve.Secp256k1, big.NewInt(1))
}

func TestSecp256k1PublicKeyIsGenerator(t *testing.T) {
	pk := secp256k1Secret1Key()
	pub := pk.PublicKey()

	if pub.Point.X.Cmp(curve.Secp256k1.G.X) != 0 {
		t.Fatal("secp256k1 secret=1 public key X != G.X")
	}
	if pub.Point.Y.Cmp(curve.Secp256k1.G.Y) != 0 {
		t.Fatal("secp256k1 secret=1 public key Y != G.Y")
	}
}

func TestSecp256k1SampleMessageRoundTrip(t *testing.T) {
	pk := secp256k1Secret1Key()
	pub := pk.PublicKey()

	sig := ecdsa.Sign("sample", &pk)

	if !ecdsa.Verify("sample", sig, &pub) {
		t.Fatal("secp256k1 sample verification failed")
	}
}

func TestSecp256k1TestMessageRoundTrip(t *testing.T) {
	pk := secp256k1Secret1Key()
	pub := pk.PublicKey()

	sig := ecdsa.Sign("test", &pk)

	if !ecdsa.Verify("test", sig, &pub) {
		t.Fatal("secp256k1 test verification failed")
	}
}

// ===================== Malleability Tests =====================

func TestSignAlwaysProducesLowS(t *testing.T) {
	halfN := new(big.Int).Div(curve.Secp256k1.N, big.NewInt(2))
	for i := 0; i < 100; i++ {
		pk := privatekey.New(curve.Secp256k1)
		sig := ecdsa.Sign("test message", &pk)
		if sig.S.Cmp(halfN) > 0 {
			t.Fatalf("iteration %d: s > N/2", i)
		}
	}
}

func TestHighSSignatureStillVerifies(t *testing.T) {
	pk := privatekey.New(curve.Secp256k1)
	pub := pk.PublicKey()
	message := "test message"

	sig := ecdsa.Sign(message, &pk)
	highS := new(big.Int).Sub(pk.Curve.N, &sig.S)
	highSSig := signature.New(sig.R, *highS)

	if !ecdsa.Verify(message, sig, &pub) {
		t.Fatal("low-S signature failed verification")
	}
	if !ecdsa.Verify(message, highSSig, &pub) {
		t.Fatal("high-S signature failed verification")
	}
}

// ===================== Public Key Validation Tests =====================

func TestRejectOffCurvePublicKey(t *testing.T) {
	pk := privatekey.New(curve.Secp256k1)
	pub := pk.PublicKey()
	message := "test message"

	sig := ecdsa.Sign(message, &pk)

	offCurvePoint := point.Point{
		X: new(big.Int).Set(pub.Point.X),
		Y: new(big.Int).Add(pub.Point.Y, big.NewInt(1)),
		Z: big.NewInt(0),
	}
	offCurveKey := publickey.PublicKey{Point: offCurvePoint, Curve: pub.Curve}

	if ecdsa.Verify(message, sig, &offCurveKey) {
		t.Fatal("Accepted off-curve public key")
	}
}

func TestFromStringRejectsOffCurvePoint(t *testing.T) {
	pk := privatekey.New(curve.Secp256k1)
	pub := pk.PublicKey()
	baseLength := 2 * pub.Curve.Length()
	badY := new(big.Int).Add(pub.Point.Y, big.NewInt(1))
	badYHex := fmt.Sprintf("%0*s", baseLength, utils.HexFromInt(badY))
	badHex := fmt.Sprintf("%0*s", baseLength, utils.HexFromInt(pub.Point.X)) + badYHex

	assertPanics(t, "FromString with off-curve point", func() {
		publickey.FromString(badHex, pub.Curve, true)
	})
}

func TestFromStringRejectsInfinityPoint(t *testing.T) {
	zeroHex := strings.Repeat("00", 2*curve.Secp256k1.Length())
	assertPanics(t, "FromString with infinity point", func() {
		publickey.FromString(zeroHex, curve.Secp256k1, true)
	})
}

// ===================== Forgery Attempt Tests =====================

func forgerySetup() (privatekey.PrivateKey, publickey.PublicKey, string, signature.Signature) {
	pk := privatekey.New(curve.Secp256k1)
	pub := pk.PublicKey()
	message := "authentic message"
	sig := ecdsa.Sign(message, &pk)
	return pk, pub, message, sig
}

func TestRejectZeroSignature(t *testing.T) {
	_, pub, message, _ := forgerySetup()
	zero := *big.NewInt(0)
	if ecdsa.Verify(message, signature.New(zero, zero), &pub) {
		t.Fatal("Accepted zero signature")
	}
}

func TestRejectREqualsZero(t *testing.T) {
	_, pub, message, sig := forgerySetup()
	zero := *big.NewInt(0)
	if ecdsa.Verify(message, signature.New(zero, sig.S), &pub) {
		t.Fatal("Accepted r=0")
	}
}

func TestRejectSEqualsZero(t *testing.T) {
	_, pub, message, sig := forgerySetup()
	zero := *big.NewInt(0)
	if ecdsa.Verify(message, signature.New(sig.R, zero), &pub) {
		t.Fatal("Accepted s=0")
	}
}

func TestRejectREqualsN(t *testing.T) {
	_, pub, message, sig := forgerySetup()
	N := *new(big.Int).Set(pub.Curve.N)
	if ecdsa.Verify(message, signature.New(N, sig.S), &pub) {
		t.Fatal("Accepted r=N")
	}
}

func TestRejectSEqualsN(t *testing.T) {
	_, pub, message, sig := forgerySetup()
	N := *new(big.Int).Set(pub.Curve.N)
	if ecdsa.Verify(message, signature.New(sig.R, N), &pub) {
		t.Fatal("Accepted s=N")
	}
}

func TestRejectRExceedsN(t *testing.T) {
	_, pub, message, sig := forgerySetup()
	Np1 := *new(big.Int).Add(pub.Curve.N, big.NewInt(1))
	if ecdsa.Verify(message, signature.New(Np1, sig.S), &pub) {
		t.Fatal("Accepted r>N")
	}
}

func TestRejectArbitrarySignature(t *testing.T) {
	_, pub, message, _ := forgerySetup()
	one := *big.NewInt(1)
	if ecdsa.Verify(message, signature.New(one, one), &pub) {
		t.Fatal("Accepted arbitrary signature (1,1)")
	}
}

func TestRejectBoundarySignature(t *testing.T) {
	_, pub, message, _ := forgerySetup()
	Nm1 := *new(big.Int).Sub(pub.Curve.N, big.NewInt(1))
	Nm1b := *new(big.Int).Sub(pub.Curve.N, big.NewInt(1))
	if ecdsa.Verify(message, signature.New(Nm1, Nm1b), &pub) {
		t.Fatal("Accepted boundary signature (N-1, N-1)")
	}
}

func TestWrongKeyRejected(t *testing.T) {
	_, _, message, sig := forgerySetup()
	otherKey := privatekey.New(curve.Secp256k1).PublicKey()
	if ecdsa.Verify(message, sig, &otherKey) {
		t.Fatal("Accepted wrong key")
	}
}

// ===================== Hedged Signature Tests =====================

func TestSameInputsProduceDifferentSignatures(t *testing.T) {
	pk := privatekey.New(curve.Secp256k1)
	message := "test message"

	sig1 := ecdsa.Sign(message, &pk)
	sig2 := ecdsa.Sign(message, &pk)

	if sig1.R.Cmp(&sig2.R) == 0 && sig1.S.Cmp(&sig2.S) == 0 {
		t.Fatal("Hedged signatures should differ for same message/key")
	}
}

func TestDifferentMessagesDifferentSignatures(t *testing.T) {
	pk := privatekey.New(curve.Secp256k1)

	sig1 := ecdsa.Sign("message 1", &pk)
	sig2 := ecdsa.Sign("message 2", &pk)

	if sig1.R.Cmp(&sig2.R) == 0 && sig1.S.Cmp(&sig2.S) == 0 {
		t.Fatal("Different messages produced same signature")
	}
}

func TestDifferentKeysDifferentSignatures(t *testing.T) {
	message := "test message"

	pk1 := privatekey.New(curve.Secp256k1)
	pk2 := privatekey.New(curve.Secp256k1)
	sig1 := ecdsa.Sign(message, &pk1)
	sig2 := ecdsa.Sign(message, &pk2)

	if sig1.R.Cmp(&sig2.R) == 0 && sig1.S.Cmp(&sig2.S) == 0 {
		t.Fatal("Different keys produced same signature")
	}
}

// ===================== Edge Case Message Tests =====================

func signAndVerify(t *testing.T, pk *privatekey.PrivateKey, pub *publickey.PublicKey, message string) {
	t.Helper()
	sig := ecdsa.Sign(message, pk)
	if !ecdsa.Verify(message, sig, pub) {
		t.Fatalf("Verification failed for message %q", message)
	}
	if ecdsa.Verify(message+"x", sig, pub) {
		t.Fatalf("Verification succeeded for tampered message %q", message+"x")
	}
}

func TestEmptyMessage(t *testing.T) {
	pk := privatekey.New(curve.Secp256k1)
	pub := pk.PublicKey()
	signAndVerify(t, &pk, &pub, "")
}

func TestSingleCharMessage(t *testing.T) {
	pk := privatekey.New(curve.Secp256k1)
	pub := pk.PublicKey()
	signAndVerify(t, &pk, &pub, "a")
}

func TestUnicodeMessage(t *testing.T) {
	pk := privatekey.New(curve.Secp256k1)
	pub := pk.PublicKey()
	signAndVerify(t, &pk, &pub, "\u00e9\u00e8\u00ea\u00eb")
}

func TestEmojiMessage(t *testing.T) {
	pk := privatekey.New(curve.Secp256k1)
	pub := pk.PublicKey()
	signAndVerify(t, &pk, &pub, "\U0001f512\U0001f511")
}

func TestNullByteMessage(t *testing.T) {
	pk := privatekey.New(curve.Secp256k1)
	pub := pk.PublicKey()
	signAndVerify(t, &pk, &pub, "before\x00after")
}

func TestLongMessage(t *testing.T) {
	pk := privatekey.New(curve.Secp256k1)
	pub := pk.PublicKey()
	signAndVerify(t, &pk, &pub, strings.Repeat("a", 10000))
}

func TestNewlinesAndWhitespace(t *testing.T) {
	pk := privatekey.New(curve.Secp256k1)
	pub := pk.PublicKey()
	signAndVerify(t, &pk, &pub, "  line1\n\tline2\r\n  ")
}

// ===================== Serialization Round Trip Tests =====================

func TestSignatureDerRoundTrip(t *testing.T) {
	pk := privatekey.New(curve.Secp256k1)
	pub := pk.PublicKey()
	message := "round-trip test"
	sig := ecdsa.Sign(message, &pk)

	der := sig.ToDer()
	restored := signature.FromDer(der)
	if restored.R.Cmp(&sig.R) != 0 || restored.S.Cmp(&sig.S) != 0 {
		t.Fatal("DER round-trip failed")
	}
	if !ecdsa.Verify(message, restored, &pub) {
		t.Fatal("DER round-trip verification failed")
	}
}

func TestSignatureBase64RoundTrip(t *testing.T) {
	pk := privatekey.New(curve.Secp256k1)
	pub := pk.PublicKey()
	message := "round-trip test"
	sig := ecdsa.Sign(message, &pk)

	b64 := sig.ToBase64()
	restored := signature.FromBase64(b64)
	if restored.R.Cmp(&sig.R) != 0 || restored.S.Cmp(&sig.S) != 0 {
		t.Fatal("Base64 round-trip failed")
	}
	if !ecdsa.Verify(message, restored, &pub) {
		t.Fatal("Base64 round-trip verification failed")
	}
}

func TestSignatureDerWithRecoveryIdRoundTrip(t *testing.T) {
	pk := privatekey.New(curve.Secp256k1)
	message := "round-trip test"
	sig := ecdsa.Sign(message, &pk)

	der := sig.ToDer(true)
	restored := signature.FromDer(der, true)
	if restored.R.Cmp(&sig.R) != 0 || restored.S.Cmp(&sig.S) != 0 {
		t.Fatal("DER with recovery ID round-trip failed")
	}
	if restored.RecoveryId != sig.RecoveryId {
		t.Fatalf("Recovery ID mismatch: got %d, expected %d", restored.RecoveryId, sig.RecoveryId)
	}
}

func TestPrivateKeyPemRoundTrip(t *testing.T) {
	pk := privatekey.New(curve.Secp256k1)
	pem := pk.ToPem()
	restored := privatekey.FromPem(pem)
	if restored.Secret.Cmp(pk.Secret) != 0 {
		t.Fatal("Private key PEM round-trip: secret mismatch")
	}
	if restored.Curve.Name != pk.Curve.Name {
		t.Fatal("Private key PEM round-trip: curve name mismatch")
	}
}

func TestPrivateKeyDerRoundTrip(t *testing.T) {
	pk := privatekey.New(curve.Secp256k1)
	der := pk.ToDer()
	restored := privatekey.FromDer(der)
	if restored.Secret.Cmp(pk.Secret) != 0 {
		t.Fatal("Private key DER round-trip: secret mismatch")
	}
}

func TestPublicKeyPemRoundTrip(t *testing.T) {
	pk := privatekey.New(curve.Secp256k1)
	pub := pk.PublicKey()
	pem := pub.ToPem()
	restored := publickey.FromPem(pem)
	if restored.Point.X.Cmp(pub.Point.X) != 0 || restored.Point.Y.Cmp(pub.Point.Y) != 0 {
		t.Fatal("Public key PEM round-trip: point mismatch")
	}
}

func TestPublicKeyCompressedRoundTrip(t *testing.T) {
	pk := privatekey.New(curve.Secp256k1)
	pub := pk.PublicKey()
	message := "round-trip test"
	sig := ecdsa.Sign(message, &pk)

	compressed := pub.ToCompressed()
	restored := publickey.FromCompressed(compressed, pub.Curve)
	if restored.Point.X.Cmp(pub.Point.X) != 0 || restored.Point.Y.Cmp(pub.Point.Y) != 0 {
		t.Fatal("Compressed round-trip: point mismatch")
	}
	if !ecdsa.Verify(message, sig, &restored) {
		t.Fatal("Compressed round-trip: verification failed")
	}
}

func TestPublicKeyCompressedEvenAndOdd(t *testing.T) {
	for i := 0; i < 20; i++ {
		pk := privatekey.New(curve.Secp256k1)
		pub := pk.PublicKey()
		compressed := pub.ToCompressed()
		restored := publickey.FromCompressed(compressed, pub.Curve)
		if restored.Point.X.Cmp(pub.Point.X) != 0 || restored.Point.Y.Cmp(pub.Point.Y) != 0 {
			t.Fatalf("Compressed even/odd round-trip failed at iteration %d", i)
		}
	}
}

func TestPrime256v1KeyRoundTrip(t *testing.T) {
	pk := privatekey.New(curve.Prime256v1)
	pem := pk.ToPem()
	restored := privatekey.FromPem(pem)
	if restored.Secret.Cmp(pk.Secret) != 0 {
		t.Fatal("prime256v1 PEM round-trip: secret mismatch")
	}
	if restored.Curve.Name != "prime256v1" {
		t.Fatalf("prime256v1 PEM round-trip: curve name mismatch: got %s", restored.Curve.Name)
	}
}

// ===================== Tonelli-Shanks Tests =====================

func TestTonelliShanksPrimeCongruent1Mod4(t *testing.T) {
	// P = 17: 17 - 1 = 16 = 2^4, S = 4, exercises full Tonelli-Shanks
	P := big.NewInt(17)
	halfP := new(big.Int).Div(new(big.Int).Sub(P, big.NewInt(1)), big.NewInt(2))
	for v := int64(1); v < 17; v++ {
		value := big.NewInt(v)
		if new(big.Int).Exp(value, halfP, P).Cmp(big.NewInt(1)) == 0 {
			root := ecmath.ModularSquareRoot(value, P)
			result := new(big.Int).Mul(root, root)
			result.Mod(result, P)
			if result.Cmp(value) != 0 {
				t.Fatalf("Tonelli-Shanks P=17: sqrt(%d)^2 mod 17 = %d, expected %d", v, result, value)
			}
		}
	}
}

func TestTonelliShanksPrimeCongruent5Mod8(t *testing.T) {
	// P = 13: 13 - 1 = 12 = 3 * 2^2, S = 2
	P := big.NewInt(13)
	halfP := new(big.Int).Div(new(big.Int).Sub(P, big.NewInt(1)), big.NewInt(2))
	for v := int64(1); v < 13; v++ {
		value := big.NewInt(v)
		if new(big.Int).Exp(value, halfP, P).Cmp(big.NewInt(1)) == 0 {
			root := ecmath.ModularSquareRoot(value, P)
			result := new(big.Int).Mul(root, root)
			result.Mod(result, P)
			if result.Cmp(value) != 0 {
				t.Fatalf("Tonelli-Shanks P=13: sqrt(%d)^2 mod 13 = %d, expected %d", v, result, value)
			}
		}
	}
}

func TestTonelliShanksPrimeCongruent3Mod4(t *testing.T) {
	// P = 7: fast path (S = 1)
	P := big.NewInt(7)
	halfP := new(big.Int).Div(new(big.Int).Sub(P, big.NewInt(1)), big.NewInt(2))
	for v := int64(1); v < 7; v++ {
		value := big.NewInt(v)
		if new(big.Int).Exp(value, halfP, P).Cmp(big.NewInt(1)) == 0 {
			root := ecmath.ModularSquareRoot(value, P)
			result := new(big.Int).Mul(root, root)
			result.Mod(result, P)
			if result.Cmp(value) != 0 {
				t.Fatalf("Tonelli-Shanks P=7: sqrt(%d)^2 mod 7 = %d, expected %d", v, result, value)
			}
		}
	}
}

func TestTonelliShanksZeroValue(t *testing.T) {
	result := ecmath.ModularSquareRoot(big.NewInt(0), big.NewInt(17))
	if result.Cmp(big.NewInt(0)) != 0 {
		t.Fatalf("Tonelli-Shanks zero value: expected 0, got %v", result)
	}
}

// ===================== Hash Truncation Tests =====================

func TestSignVerifyWithSha512(t *testing.T) {
	pk := privatekey.New(curve.Secp256k1)
	pub := pk.PublicKey()
	message := "test message"

	sig := ecdsa.Sign(message, &pk, utils.Sha512)

	if !ecdsa.Verify(message, sig, &pub, utils.Sha512) {
		t.Fatal("SHA-512 sign/verify failed")
	}
	if ecdsa.Verify("wrong message", sig, &pub, utils.Sha512) {
		t.Fatal("SHA-512 verify accepted wrong message")
	}
}

func TestSha512SignaturesAreHedged(t *testing.T) {
	pk := privatekey.New(curve.Secp256k1)
	message := "test message"

	sig1 := ecdsa.Sign(message, &pk, utils.Sha512)
	sig2 := ecdsa.Sign(message, &pk, utils.Sha512)

	if sig1.R.Cmp(&sig2.R) == 0 && sig1.S.Cmp(&sig2.S) == 0 {
		t.Fatal("SHA-512 hedged signatures should differ for same message/key")
	}
}

func TestHashMismatchFails(t *testing.T) {
	pk := privatekey.New(curve.Secp256k1)
	pub := pk.PublicKey()
	message := "test message"

	sig := ecdsa.Sign(message, &pk, utils.Sha256)
	if ecdsa.Verify(message, sig, &pub, utils.Sha512) {
		t.Fatal("Hash mismatch should fail but passed")
	}
}

// ===================== Prime256v1 Security Tests =====================

func TestPrime256v1SignVerify(t *testing.T) {
	pk := privatekey.New(curve.Prime256v1)
	pub := pk.PublicKey()
	message := "test message"

	sig := ecdsa.Sign(message, &pk)

	halfN := new(big.Int).Div(curve.Prime256v1.N, big.NewInt(2))
	if sig.S.Cmp(halfN) > 0 {
		t.Fatal("prime256v1 signature s > N/2")
	}
	if !ecdsa.Verify(message, sig, &pub) {
		t.Fatal("prime256v1 sign/verify failed")
	}
}

func TestPrime256v1SignaturesAreHedged(t *testing.T) {
	pk := privatekey.New(curve.Prime256v1)
	message := "test message"

	sig1 := ecdsa.Sign(message, &pk)
	sig2 := ecdsa.Sign(message, &pk)

	if sig1.R.Cmp(&sig2.R) == 0 && sig1.S.Cmp(&sig2.S) == 0 {
		t.Fatal("prime256v1 hedged signatures should differ for same message/key")
	}
}

func TestWrongCurveKeyFails(t *testing.T) {
	k1Key := privatekey.New(curve.Secp256k1)
	p256Key := privatekey.New(curve.Prime256v1)
	message := "cross-curve test"

	sig := ecdsa.Sign(message, &k1Key)
	p256Pub := p256Key.PublicKey()
	if ecdsa.Verify(message, sig, &p256Pub) {
		t.Fatal("Cross-curve verification should fail but passed")
	}
}
