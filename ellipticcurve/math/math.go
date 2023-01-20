package math

import (
	"math/big"

	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/point"
)

type Mather interface {
	Multiply(p point.Point, n *big.Int, N *big.Int, A *big.Int, P *big.Int) point.Point
	Add(p point.Point, q point.Point, A *big.Int, P *big.Int) point.Point
	Inv(x *big.Int, n *big.Int) *big.Int
}

type Math struct{}

//
// Fast way to multily point and scalar in elliptic curves
//
// Params:
//
// - `p`: First Point to mutiply
//
// - `n`: Scalar to mutiply
//
// - `N`: Order of the elliptic curve
//
// - `A`: Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod P)
//
// - `P`: Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod P)
//
// Returns:
//
// - Point that represents the multiplication of a point and a scalar
//
func Multiply(p point.Point, n *big.Int, N *big.Int, A *big.Int, P *big.Int) point.Point {
	return fromJacobian(jacobianMultiply(toJacobian(p), n, N, A, P), P)
}

//
// Fast way to add two points in elliptic curves
//
// Params:
//
// - `p`: First Point you want to add
//
// - `q`: Second Point you want to add
//
// - `A`: Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod P)
//
// - `P`: Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod P)
//
// Returns:
//
// - Point that represents the sum of First and Second Point
//
func Add(p point.Point, q point.Point, A *big.Int, P *big.Int) point.Point {
	return fromJacobian(jacobianAdd(toJacobian(p), toJacobian(q), A, P), P)
}

//
// Extended Euclidean Algorithm. It's the 'division' in elliptic curves
//
// Params:
//
// - `x`: Divisor
//
// - `n`: Mod for division
//
// Returns:
//
// - Value representing the division
//
func Inv(x *big.Int, n *big.Int) *big.Int {
	if x.Cmp(big.NewInt(0)) == 0 {
		return big.NewInt(0)
	}
	one := big.NewInt(1)
	lm := big.NewInt(1)
	hm := big.NewInt(0)
	low := new(big.Int).Mod(x, n)
	high := n
	var r, nm, nw *big.Int
	for low.Cmp(one) > 0 {
		r = new(big.Int).Div(high, low)
		nm = new(big.Int).Sub(hm, new(big.Int).Mul(lm, r))
		nw = new(big.Int).Sub(high, new(big.Int).Mul(low, r))
		high = low
		hm = lm
		low = nw
		lm = nm
	}
	return new(big.Int).Mod(lm, n)
}

//
// Convert point to Jacobian coordinates
//
// Params:
//
// - `p`: the point you want to transform
//
// Returns:
//
// - Point in Jacobian coordinates
//
func toJacobian(p point.Point) point.Point {
	return point.Point{X: p.X, Y: p.Y, Z: big.NewInt(1)}
}

//
// Convert point to Jacobian coordinates
//
// Params:
//
// - `p`: the point you want to transform
//
// - `P`: Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod P)
//
// Returns:
//
// - Point in Jacobian coordinates
//
func fromJacobian(p point.Point, P *big.Int) point.Point {
	z := Inv(p.Z, P)

	x, y := new(big.Int), new(big.Int)
	x.Exp(z, big.NewInt(2), nil).Mul(x, p.X).Mod(x, P)
	y.Exp(z, big.NewInt(3), nil).Mul(y, p.Y).Mod(y, P)

	return point.Point{X: x, Y: y, Z: big.NewInt(0)}
}

//
// Double a point in elliptic curves
//
// Params:
//
// - `p`: Point you want to double
//
// - `A`: Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod P)
//
// - `P`: Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod P)
//
// Returns:
//
// - Point that represents the sum of First and Second Point
//
func jacobianDouble(p point.Point, A *big.Int, P *big.Int) point.Point {
	if p.Y.Cmp(big.NewInt(0)) == 0 {
		return point.Point{X: big.NewInt(0), Y: big.NewInt(0), Z: big.NewInt(0)}
	}

	ysq, S, M, nx, ny, nz := new(big.Int), new(big.Int), new(big.Int), new(big.Int), new(big.Int), new(big.Int)
	M1, M2, ny1, ny2 := new(big.Int), new(big.Int), new(big.Int), new(big.Int)

	ysq.Exp(p.Y, big.NewInt(2), nil).Mod(ysq, P)

	S.Mul(big.NewInt(4), p.X).Mul(S, ysq).Mod(S, P)

	M1.Exp(p.X, big.NewInt(2), nil).Mul(M1, big.NewInt(3))
	M2.Exp(p.Z, big.NewInt(4), nil).Mul(M2, A)
	M.Add(M1, M2).Mod(M, P)

	nx.Sub(new(big.Int).Exp(M, big.NewInt(2), nil), new(big.Int).Mul(S, big.NewInt(2))).Mod(nx, P)

	ny1.Sub(S, nx).Mul(ny1, M)
	ny2.Exp(ysq, big.NewInt(2), nil).Mul(ny2, big.NewInt(8))
	ny.Sub(ny1, ny2).Mod(ny, P)

	nz.Mul(big.NewInt(2), p.Y).Mul(nz, p.Z).Mod(nz, P)

	return point.Point{X: nx, Y: ny, Z: nz}
}

//
// Add two points in elliptic curves
//
// Params:
//
// - `p`: First Point you want to add
//
// - `q`: Second Point you want to add
//
// - `A`: Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod P)
//
// - `P`: Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod P)
//
// Returns:
//
// - Point that represents the sum of First and Second Point
//
func jacobianAdd(p point.Point, q point.Point, A *big.Int, P *big.Int) point.Point {
	zero := big.NewInt(0)
	if p.Y.Cmp(zero) == 0 {
		return q
	}
	if q.Y.Cmp(zero) == 0 {
		return p
	}

	U1, U2, S1, S2 := new(big.Int), new(big.Int), new(big.Int), new(big.Int)

	U1.Exp(q.Z, big.NewInt(2), nil).Mul(U1, p.X).Mod(U1, P)
	U2.Exp(p.Z, big.NewInt(2), nil).Mul(U2, q.X).Mod(U2, P)
	S1.Exp(q.Z, big.NewInt(3), nil).Mul(S1, p.Y).Mod(S1, P)
	S2.Exp(p.Z, big.NewInt(3), nil).Mul(S2, q.Y).Mod(S2, P)

	if U1.Cmp(U2) == 0 {
		if S1.Cmp(S2) != 0 {
			return point.Point{X: big.NewInt(0), Y: big.NewInt(0), Z: big.NewInt(1)}
		}
		return jacobianDouble(p, A, P)
	}

	H, R, H2, H3, U1H2, nx, ny, nz := new(big.Int), new(big.Int), new(big.Int), new(big.Int), new(big.Int), new(big.Int), new(big.Int), new(big.Int)
	ny1 := new(big.Int)
	H.Sub(U2, U1)
	R.Sub(S2, S1)
	H2.Mul(H, H).Mod(H2, P)
	H3.Mul(H, H2).Mod(H3, P)
	U1H2.Mul(U1, H2).Mod(U1H2, P)
	nx.Sub(new(big.Int).Exp(R, big.NewInt(2), nil), H3).Sub(nx, new(big.Int).Mul(big.NewInt(2), U1H2)).Mod(nx, P)
	ny1.Sub(U1H2, nx).Mul(ny1, R)
	ny.Sub(ny1, new(big.Int).Mul(S1, H3)).Mod(ny, P)
	nz.Mul(H, p.Z).Mul(nz, q.Z).Mod(nz, P)
	return point.Point{X: nx, Y: ny, Z: nz}
}

//
// Multily point and scalar in elliptic curves
//
// Params:
//
// - `p`: First Point to mutiply
//
// - `n`: Scalar to mutiply
//
// - `N`: Order of the elliptic curve
//
// - `A`: Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod P)
//
// - `P`: Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod P)
//
// Returns:
//
// - Point that represents the sum of First and Second Point
//
func jacobianMultiply(p point.Point, n *big.Int, N *big.Int, A *big.Int, P *big.Int) point.Point {
	zero := big.NewInt(0)
	if p.Y.Cmp(zero) == 0 || n.Cmp(zero) == 0 {
		return point.Point{X: big.NewInt(0), Y: big.NewInt(0), Z: big.NewInt(1)}
	}
	if n.Cmp(big.NewInt(1)) == 0 {
		return p
	}
	if n.Cmp(zero) < 0 || n.Cmp(N) >= 0 {
		return jacobianMultiply(p, new(big.Int).Mod(n, N), N, A, P)
	}
	if new(big.Int).Mod(n, big.NewInt(2)).Cmp(zero) == 0 {
		return jacobianDouble(
			jacobianMultiply(
				p,
				new(big.Int).Div(n, big.NewInt(2)),
				N,
				A,
				P,
			),
			A,
			P,
		)
	}
	return jacobianAdd(
		jacobianDouble(
			jacobianMultiply(
				p,
				new(big.Int).Div(n, big.NewInt(2)),
				N,
				A,
				P,
			),
			A,
			P,
		),
		p,
		A,
		P,
	)
}
