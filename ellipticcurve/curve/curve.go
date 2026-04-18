//
// Elliptic Curve Equation
//
// y^2 = x^3 + A*x + B (mod P)
//

package curve

import (
	"fmt"
	"math/big"

	ecmath "github.com/starkbank/ecdsa-go/v2/ellipticcurve/math"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/point"
)

type CurveFp struct {
	A          *big.Int
	B          *big.Int
	P          *big.Int
	N          *big.Int
	G          point.Point
	Name       string
	NistName   string
	Oid        []int64
	NBitLength int

	// GeneratorCache caches the precomputed 2^4-ary window table of G,
	// populated lazily by ecmath.MultiplyGenerator.
	GeneratorCache *ecmath.GeneratorCache
}

// Contains verifies if the point p is on the curve
func (obj CurveFp) Contains(p point.Point) bool {
	zero := big.NewInt(0)
	max := new(big.Int).Sub(obj.P, big.NewInt(1))
	if p.X.Cmp(zero) < 0 || p.X.Cmp(max) > 0 {
		return false
	}
	if p.Y.Cmp(zero) < 0 || p.Y.Cmp(max) > 0 {
		return false
	}
	// y^2 - (x^3 + A*x + B) mod P == 0
	y2 := new(big.Int).Mul(p.Y, p.Y)
	x3 := new(big.Int).Exp(p.X, big.NewInt(3), nil)
	ax := new(big.Int).Mul(obj.A, p.X)
	rhs := new(big.Int).Add(x3, ax)
	rhs.Add(rhs, obj.B)
	result := new(big.Int).Sub(y2, rhs)
	result.Mod(result, obj.P)
	return result.Cmp(zero) == 0
}

// Length returns the byte length of the curve order
func (obj CurveFp) Length() int {
	return (1 + len(fmt.Sprintf("%x", obj.N))) / 2
}

// Y computes the y coordinate given x and parity (isEven)
func (obj CurveFp) Y(x *big.Int, isEven bool) *big.Int {
	// ySquared = (x^3 + A*x + B) % P
	ySquared := new(big.Int).Exp(x, big.NewInt(3), obj.P)
	ax := new(big.Int).Mul(obj.A, x)
	ySquared.Add(ySquared, ax).Add(ySquared, obj.B).Mod(ySquared, obj.P)

	y := ecmath.ModularSquareRoot(ySquared, obj.P)

	yIsEven := new(big.Int).Mod(y, big.NewInt(2)).Cmp(big.NewInt(0)) == 0
	if isEven != yIsEven {
		y.Sub(obj.P, y)
	}
	return y
}

func New(name string, AHex string, BHex string, PHex string, NHex string, GxHex string, GyHex string, oid []int64, nistName string) CurveFp {
	A, _ := new(big.Int).SetString(AHex, 0)
	B, _ := new(big.Int).SetString(BHex, 0)
	P, _ := new(big.Int).SetString(PHex, 0)
	N, _ := new(big.Int).SetString(NHex, 0)
	Gx, _ := new(big.Int).SetString(GxHex, 0)
	Gy, _ := new(big.Int).SetString(GyHex, 0)

	return CurveFp{
		Name:           name,
		NistName:       nistName,
		A:              A,
		B:              B,
		P:              P,
		N:              N,
		G:              point.Point{X: Gx, Y: Gy, Z: big.NewInt(0)},
		Oid:            oid,
		NBitLength:     N.BitLen(),
		GeneratorCache: &ecmath.GeneratorCache{},
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
	"prime256v1",
	"0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
	"0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
	"0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
	"0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
	"0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
	"0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
	[]int64{1, 2, 840, 10045, 3, 1, 7},
	"P-256",
)

var P256 = Prime256v1

var supportedCurves = []CurveFp{
	Secp256k1,
	Prime256v1,
}

// Add registers a new curve so it can be looked up by OID
func Add(c CurveFp) {
	supportedCurves = append(supportedCurves, c)
}

// GetByOid returns the curve matching the given OID
func GetByOid(oid []int64) CurveFp {
	for _, c := range supportedCurves {
		if IsOidEqual(c.Oid, oid) {
			return c
		}
	}
	var names []string
	for _, c := range supportedCurves {
		names = append(names, c.Name)
	}
	panic(fmt.Sprintf("Unknown curve with oid %v; The following are registered: %v",
		oid,
		names,
	))
}

// CurveByOid is an alias for GetByOid for backward compatibility
func CurveByOid(oid []int64) CurveFp {
	return GetByOid(oid)
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
