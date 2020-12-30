// 
// Eliptic Curve Equation
// 
// y^2 = x^3 + A*x + B (mod P)
//

package elipticcurve

import (
	"math/big"
)

type CurveFper interface {
	
	Contains(p Point) bool
	Length() int
}

type CurveFp struct {
	A *big.Int
	B *big.Int
	P *big.Int
	N *big.Int
	Gx *big.Int
	Gy *big.Int
	Name string
	NistName string
	Oid []int64
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
func (self CurveFp) Contains(p Point) bool {
	u := new(big.Int)
	v := u.Exp(p.Y, big.NewInt(2), nil)
	w := u.Exp(p.X, big.NewInt(3), nil)
	w = u.Add(w, self.A)
	w = u.Add(w, u.Mul(self.A, p.X))
	w = u.Add(w, self.B)
	v = u.Sub(v, w)
	v = u.Mod(v, self.P)

	return v == big.NewInt(0)
}

func (self CurveFp) Length() int {
	return (1 + len(self.N.String())) / 2
}

func Secp256k1() CurveFp {
	Name := "secp256k1"
	A := big.NewInt(0)
	B := big.NewInt(7)
	P,_ := new(big.Int).SetString("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 0)
	N,_ := new(big.Int).SetString("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 0)
	Gx,_ := new(big.Int).SetString("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 0)
	Gy,_ := new(big.Int).SetString("0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 0)
	Oid := []int64{1, 3, 132, 0, 10}

	return CurveFp{
		Name: Name,
		A: A,
		B: B,
		P: P,
		N: N,
		Gx: Gx,
		Gy: Gy,
		Oid: Oid}
}

func Prime256v1() CurveFp {
	Name := "prime256k1"
	NistName := "P-256"
	A,_ := new(big.Int).SetString("0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 0)
	B,_ := new(big.Int).SetString("0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 0)
	P,_ := new(big.Int).SetString("0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 0)
	N,_ := new(big.Int).SetString("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 0)
	Gx,_ := new(big.Int).SetString("0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 0)
	Gy,_ := new(big.Int).SetString("0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 0)
	Oid := []int64{1, 2, 840, 10045, 3, 1, 7}

	return CurveFp{
		Name: Name,
		NistName: NistName,
		A: A,
		B: B,
		P: P,
		N: N,
		Gx: Gx,
		Gy: Gy,
		Oid: Oid}
}

func SupportedCurves() []CurveFp {
	return []CurveFp{
		Secp256k1(),
		Prime256v1()}
}

func CurveByOid() [][]int64 {
	var listCurveByOid [][]int64
	for _, curve := range SupportedCurves() {
		listCurveByOid = append(listCurveByOid, curve.Oid)
	}

	return listCurveByOid
}
