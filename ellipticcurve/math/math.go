package math

import (
	"math/big"

	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/point"
)

// ModularSquareRoot computes the modular square root using the Tonelli-Shanks algorithm.
// Works for all odd primes.
func ModularSquareRoot(value *big.Int, prime *big.Int) *big.Int {
	if value.Sign() == 0 {
		return big.NewInt(0)
	}
	if prime.Cmp(big.NewInt(2)) == 0 {
		return new(big.Int).Mod(value, big.NewInt(2))
	}

	// Factor out powers of 2: prime - 1 = Q * 2^S
	Q := new(big.Int).Sub(prime, big.NewInt(1))
	S := 0
	for new(big.Int).Mod(Q, big.NewInt(2)).Sign() == 0 {
		Q.Div(Q, big.NewInt(2))
		S++
	}

	if S == 1 { // prime = 3 (mod 4)
		exp := new(big.Int).Add(prime, big.NewInt(1))
		exp.Div(exp, big.NewInt(4))
		return new(big.Int).Exp(value, exp, prime)
	}

	// Find a quadratic non-residue z
	z := big.NewInt(2)
	halfP := new(big.Int).Div(new(big.Int).Sub(prime, big.NewInt(1)), big.NewInt(2))
	pMinus1 := new(big.Int).Sub(prime, big.NewInt(1))
	for new(big.Int).Exp(z, halfP, prime).Cmp(pMinus1) != 0 {
		z.Add(z, big.NewInt(1))
	}

	M := S
	c := new(big.Int).Exp(z, Q, prime)
	t := new(big.Int).Exp(value, Q, prime)
	Qp1h := new(big.Int).Add(Q, big.NewInt(1))
	Qp1h.Div(Qp1h, big.NewInt(2))
	R := new(big.Int).Exp(value, Qp1h, prime)

	for {
		if t.Cmp(big.NewInt(1)) == 0 {
			return R
		}

		// Find the least i such that t^(2^i) = 1 (mod prime)
		i := 1
		temp := new(big.Int).Mul(t, t)
		temp.Mod(temp, prime)
		for temp.Cmp(big.NewInt(1)) != 0 {
			temp.Mul(temp, temp).Mod(temp, prime)
			i++
		}

		b := new(big.Int).Exp(c, new(big.Int).Lsh(big.NewInt(1), uint(M-i-1)), prime)
		M = i
		c = new(big.Int).Mul(b, b)
		c.Mod(c, prime)
		t.Mul(t, c).Mod(t, prime)
		R.Mul(R, b).Mod(R, prime)
	}
}

// Multiply performs fast scalar multiplication of a point in elliptic curves.
//
// p: Point to multiply
// n: Scalar to multiply
// N: Order of the elliptic curve
// A: Coefficient of the first-order term
// P: Prime number in the module
func Multiply(p point.Point, n *big.Int, N *big.Int, A *big.Int, P *big.Int) point.Point {
	return fromJacobian(jacobianMultiply(toJacobian(p), n, N, A, P), P)
}

// Add adds two points in elliptic curves.
func Add(p point.Point, q point.Point, A *big.Int, P *big.Int) point.Point {
	return fromJacobian(jacobianAdd(toJacobian(p), toJacobian(q), A, P), P)
}

// MultiplyAndAdd computes n1*p1 + n2*p2 using Shamir's trick (simultaneous double-and-add).
// Not constant-time -- use only with public scalars (e.g. verification).
func MultiplyAndAdd(p1 point.Point, n1 *big.Int, p2 point.Point, n2 *big.Int, N *big.Int, A *big.Int, P *big.Int) point.Point {
	return fromJacobian(
		shamirMultiply(
			toJacobian(p1), n1,
			toJacobian(p2), n2,
			N, A, P,
		), P,
	)
}

// Inv computes modular inverse using Fermat's little theorem: x^(n-2) mod n.
// Requires n to be prime (true for all ECDSA curve parameters).
// Uses big.Int.Exp which has more uniform execution time
// than the extended Euclidean algorithm.
func Inv(x *big.Int, n *big.Int) *big.Int {
	if x.Sign() == 0 {
		return big.NewInt(0)
	}
	exp := new(big.Int).Sub(n, big.NewInt(2))
	return new(big.Int).Exp(x, exp, n)
}

// toJacobian converts a point to Jacobian coordinates
func toJacobian(p point.Point) point.Point {
	return point.Point{X: new(big.Int).Set(p.X), Y: new(big.Int).Set(p.Y), Z: big.NewInt(1)}
}

// fromJacobian converts a point back from Jacobian coordinates
func fromJacobian(p point.Point, P *big.Int) point.Point {
	if p.Y.Sign() == 0 {
		return point.Point{X: big.NewInt(0), Y: big.NewInt(0), Z: big.NewInt(0)}
	}

	z := Inv(p.Z, P)
	z2 := new(big.Int).Mul(z, z)
	z2.Mod(z2, P)
	z3 := new(big.Int).Mul(z2, z)
	z3.Mod(z3, P)

	x := new(big.Int).Mul(p.X, z2)
	x.Mod(x, P)
	y := new(big.Int).Mul(p.Y, z3)
	y.Mod(y, P)

	return point.Point{X: x, Y: y, Z: big.NewInt(0)}
}

// jacobianDouble doubles a point in Jacobian coordinates
func jacobianDouble(p point.Point, A *big.Int, P *big.Int) point.Point {
	if p.Y.Sign() == 0 {
		return point.Point{X: big.NewInt(0), Y: big.NewInt(0), Z: big.NewInt(0)}
	}

	px, py, pz := p.X, p.Y, p.Z

	ysq := new(big.Int).Mul(py, py)
	ysq.Mod(ysq, P)

	S := new(big.Int).Mul(big.NewInt(4), px)
	S.Mul(S, ysq).Mod(S, P)

	pz2 := new(big.Int).Mul(pz, pz)
	pz2.Mod(pz2, P)

	M := new(big.Int).Mul(px, px)
	M.Mul(M, big.NewInt(3))
	tmp := new(big.Int).Mul(A, pz2)
	tmp.Mul(tmp, pz2)
	M.Add(M, tmp).Mod(M, P)

	nx := new(big.Int).Mul(M, M)
	nx.Sub(nx, new(big.Int).Mul(big.NewInt(2), S)).Mod(nx, P)

	ny := new(big.Int).Sub(S, nx)
	ny.Mul(ny, M)
	tmp2 := new(big.Int).Mul(ysq, ysq)
	tmp2.Mul(tmp2, big.NewInt(8))
	ny.Sub(ny, tmp2).Mod(ny, P)

	nz := new(big.Int).Mul(big.NewInt(2), py)
	nz.Mul(nz, pz).Mod(nz, P)

	return point.Point{X: nx, Y: ny, Z: nz}
}

// jacobianAdd adds two points in Jacobian coordinates
func jacobianAdd(p point.Point, q point.Point, A *big.Int, P *big.Int) point.Point {
	if p.Y.Sign() == 0 {
		return q
	}
	if q.Y.Sign() == 0 {
		return p
	}

	px, py, pz := p.X, p.Y, p.Z
	qx, qy, qz := q.X, q.Y, q.Z

	qz2 := new(big.Int).Mul(qz, qz)
	qz2.Mod(qz2, P)
	pz2 := new(big.Int).Mul(pz, pz)
	pz2.Mod(pz2, P)

	U1 := new(big.Int).Mul(px, qz2)
	U1.Mod(U1, P)
	U2 := new(big.Int).Mul(qx, pz2)
	U2.Mod(U2, P)

	S1 := new(big.Int).Mul(py, qz2)
	S1.Mul(S1, qz).Mod(S1, P)
	S2 := new(big.Int).Mul(qy, pz2)
	S2.Mul(S2, pz).Mod(S2, P)

	if U1.Cmp(U2) == 0 {
		if S1.Cmp(S2) != 0 {
			return point.Point{X: big.NewInt(0), Y: big.NewInt(0), Z: big.NewInt(1)}
		}
		return jacobianDouble(p, A, P)
	}

	H := new(big.Int).Sub(U2, U1)
	R := new(big.Int).Sub(S2, S1)
	H2 := new(big.Int).Mul(H, H)
	H2.Mod(H2, P)
	H3 := new(big.Int).Mul(H, H2)
	H3.Mod(H3, P)
	U1H2 := new(big.Int).Mul(U1, H2)
	U1H2.Mod(U1H2, P)

	nx := new(big.Int).Mul(R, R)
	nx.Sub(nx, H3).Sub(nx, new(big.Int).Mul(big.NewInt(2), U1H2)).Mod(nx, P)

	ny := new(big.Int).Sub(U1H2, nx)
	ny.Mul(ny, R)
	ny.Sub(ny, new(big.Int).Mul(S1, H3)).Mod(ny, P)

	nz := new(big.Int).Mul(H, pz)
	nz.Mul(nz, qz).Mod(nz, P)

	return point.Point{X: nx, Y: ny, Z: nz}
}

// jacobianMultiply multiplies point and scalar using Montgomery ladder
// for constant-time execution.
func jacobianMultiply(p point.Point, n *big.Int, N *big.Int, A *big.Int, P *big.Int) point.Point {
	if p.Y.Sign() == 0 || n.Sign() == 0 {
		return point.Point{X: big.NewInt(0), Y: big.NewInt(0), Z: big.NewInt(1)}
	}

	if n.Sign() < 0 || n.Cmp(N) >= 0 {
		n = new(big.Int).Mod(n, N)
	}

	if n.Sign() == 0 {
		return point.Point{X: big.NewInt(0), Y: big.NewInt(0), Z: big.NewInt(1)}
	}

	// Montgomery ladder: always performs one add and one double per bit
	r0 := point.Point{X: big.NewInt(0), Y: big.NewInt(0), Z: big.NewInt(1)}
	r1 := point.Point{X: new(big.Int).Set(p.X), Y: new(big.Int).Set(p.Y), Z: new(big.Int).Set(p.Z)}

	for i := n.BitLen() - 1; i >= 0; i-- {
		if n.Bit(i) == 0 {
			r1 = jacobianAdd(r0, r1, A, P)
			r0 = jacobianDouble(r0, A, P)
		} else {
			r0 = jacobianAdd(r0, r1, A, P)
			r1 = jacobianDouble(r1, A, P)
		}
	}

	return r0
}

// shamirMultiply computes n1*p1 + n2*p2 using Shamir's trick (simultaneous double-and-add).
// Not constant-time -- use only with public scalars (e.g. verification).
func shamirMultiply(jp1 point.Point, n1 *big.Int, jp2 point.Point, n2 *big.Int, N *big.Int, A *big.Int, P *big.Int) point.Point {
	if n1.Sign() < 0 || n1.Cmp(N) >= 0 {
		n1 = new(big.Int).Mod(n1, N)
	}
	if n2.Sign() < 0 || n2.Cmp(N) >= 0 {
		n2 = new(big.Int).Mod(n2, N)
	}

	jp1p2 := jacobianAdd(jp1, jp2, A, P)

	l := n1.BitLen()
	if n2.BitLen() > l {
		l = n2.BitLen()
	}

	r := point.Point{X: big.NewInt(0), Y: big.NewInt(0), Z: big.NewInt(1)}

	for i := l - 1; i >= 0; i-- {
		r = jacobianDouble(r, A, P)
		b1 := n1.Bit(i)
		b2 := n2.Bit(i)
		if b1 == 1 {
			if b2 == 1 {
				r = jacobianAdd(r, jp1p2, A, P)
			} else {
				r = jacobianAdd(r, jp1, A, P)
			}
		} else if b2 == 1 {
			r = jacobianAdd(r, jp2, A, P)
		}
	}

	return r
}
