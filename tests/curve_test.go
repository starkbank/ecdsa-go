package tests

import (
	"testing"
	"math/big"
	"../elipticcurve"
)

func TestSecp256k1(t *testing.T) {
	point := elipticcurve.Point{
		X: big.NewInt(12),
		Y: big.NewInt(43),
		Z: big.NewInt(432)}

	curve := elipticcurve.Secp256k1()

	if curve.Contains(point) == true {
		t.Error("Point should not be in the curve")
	}

	if curve.Length() != 39 {
		t.Error("Wrong curve")
	}
}

func TestPrime256v1(t *testing.T) {
	point := elipticcurve.Point{
		X: big.NewInt(12),
		Y: big.NewInt(43),
		Z: big.NewInt(432)}

	curve := elipticcurve.Prime256v1()

	if curve.Length() != 39 {
		t.Error("Wrong curve")
	}

	if curve.Contains(point) == true {
		t.Error("Point should not be in the curve")
	}
}
