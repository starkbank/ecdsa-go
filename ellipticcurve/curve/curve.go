//
// Eliptic Curve Equation
//
// y^2 = x^3 + A*x + B (mod P)
//

package curve

import (
	"fmt"
	"math/big"

	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/point"
)

type CurveFper interface {
	Contains(p point.Point) bool
	Length() int
}

type CurveFp struct {
	A        *big.Int
	B        *big.Int
	P        *big.Int
	N        *big.Int
	Gx       *big.Int
	Gy       *big.Int
	G        point.Point
	Name     string
	NistName string
	Oid      []int64
}

//
// Verify if the point 'p' is on the curve
//
// Params:
//
// - `p`: Point{x,y}
//
// Returns:
//
// - boolean value whether or not the point belongs to the curve
//
func (obj CurveFp) Contains(p point.Point) bool {
	zero, max := big.NewInt(0), new(big.Int).Sub(obj.P, big.NewInt(1))
	if p.X.Cmp(zero) < 0 || p.X.Cmp(max) > 0 {
		return false
	}
	if p.Y.Cmp(zero) < 0 || p.Y.Cmp(max) > 0 {
		return false
	}
	result := new(big.Int)
	result.Exp(p.X, big.NewInt(3), nil).Add(result, new(big.Int).Mul(obj.A, p.X)).Add(result, obj.B)
	result.Sub(new(big.Int).Exp(p.Y, big.NewInt(2), nil), result).Mod(result, obj.P)
	return result.Cmp(zero) == 0
}

func (obj CurveFp) Length() int {
	return (1 + len(fmt.Sprintf("%X", obj.N))) / 2
}

func New(name string, AHex string, BHex string, PHex string, NHex string, GxHex string, GyHex string, oid []int64, nistName string) CurveFp {
	A, _ := new(big.Int).SetString(AHex, 0)
	B, _ := new(big.Int).SetString(BHex, 0)
	P, _ := new(big.Int).SetString(PHex, 0)
	N, _ := new(big.Int).SetString(NHex, 0)
	Gx, _ := new(big.Int).SetString(GxHex, 0)
	Gy, _ := new(big.Int).SetString(GyHex, 0)

	return CurveFp{
		Name: name,
		A:    A,
		B:    B,
		P:    P,
		N:    N,
		G:    point.Point{X: Gx, Y: Gy, Z: big.NewInt(0)},
		Oid:  oid,
	}
}

var Secp256k1 = New(
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

var Prime256v1 = New(
	"prime256k1",
	"0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
	"0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
	"0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
	"0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
	"0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
	"0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
	[]int64{1, 2, 840, 10045, 3, 1, 7},
	"P-256",
)

var supportedCurves = []CurveFp{
	Secp256k1,
	Prime256v1,
}

func Add(curve CurveFp) []CurveFp {
	supportedCurves = append(supportedCurves, curve)
	return supportedCurves
}

func CurveByOid(oid []int64) CurveFp {
	for _, curve := range supportedCurves {
		if IsOidEqual(curve.Oid, oid) {
			return curve
		}
	}
	var names []string
	for _, curve := range supportedCurves {
		names = append(names, curve.Name)
	}
	panic(fmt.Sprintf("Unknown curve with oid %d; The following are registered: %s",
		oid,
		names,
	))
}

func IsOidEqual(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}
