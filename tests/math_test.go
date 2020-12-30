package tests

import (
	"testing"
	"math/big"
	. "../elipticcurve"
)

func TestMultiplyAndAdd(t *testing.T) {
	p := Point{
		X: big.NewInt(3),
		Y: big.NewInt(16),
		Z: big.NewInt(0)}

	n := big.NewInt(2)
	N := big.NewInt(3)
	A := big.NewInt(0)
	P := big.NewInt(37)

	mult := Multiply(p, n, N, A, P)
	add := Add(p, p, A, P)

	if !(mult != add) {
		t.Error("Multiplication or Addition gone wrong")
	}
}

func TestInv(t *testing.T) {
	x := big.NewInt(4)
	n := big.NewInt(7)

	ans := Inv(x, n)

	if ans.Cmp(big.NewInt(2)) != 0 {
		t.Error("Inversion gone wrong")
	}
}
