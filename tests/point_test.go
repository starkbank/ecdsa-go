package tests

import (
	"testing"
	"math/big"
	"../elipticcurve"
)

func TestPoint(t *testing.T) {
	point := elipticcurve.Point{
		X: big.NewInt(12),
		Y: big.NewInt(43),
		Z: big.NewInt(432)}

	if point.X.Cmp(big.NewInt(12)) != 0 {
		t.Error("X value is wrong")
	} 
	
	if point.Y.Cmp(big.NewInt(43)) != 0 {
		t.Error("Y value is wrong")
	}
	
	if point.Z.Cmp(big.NewInt(432)) != 0 {
		t.Error("Z value is wrong")
	}
}
