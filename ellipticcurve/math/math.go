package math

import (
	"math/big"
	"sync"

	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/point"
)

// generatorWindowBits is the window size used by the fixed-base 2^w-ary
// scalar multiplication for the curve generator.
const generatorWindowBits = 4

// GeneratorCache holds the precomputed 2^w-ary window table of a curve
// generator G in Jacobian coordinates. It is populated lazily on the first
// call to MultiplyGenerator and shared across copies of CurveFp via pointer.
type GeneratorCache struct {
	Once  sync.Once
	Table []point.Point
}

// curveMode carries precomputed per-call curve parameters used by the
// Jacobian primitives so that expensive comparisons / subtractions don't
// happen once per double or add.
type curveMode struct {
	A       *big.Int
	P       *big.Int
	aIsZero bool
	aIsMin3 bool // true when A ≡ -3 (mod P), i.e. A == P - 3
}

func newCurveMode(A *big.Int, P *big.Int) curveMode {
	m := curveMode{A: A, P: P}
	if A.Sign() == 0 {
		m.aIsZero = true
		return m
	}
	// Check A == P - 3 without allocating a subtraction helper each time by
	// computing (A + 3) and comparing against P. Allocation happens once per
	// outer call, not once per double.
	aPlus3 := new(big.Int).Add(A, big.NewInt(3))
	if aPlus3.Cmp(P) == 0 {
		m.aIsMin3 = true
	}
	return m
}

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
	mode := newCurveMode(A, P)
	return fromJacobian(jacobianMultiply(toJacobian(p), n, N, mode), P)
}

// Add adds two points in elliptic curves.
func Add(p point.Point, q point.Point, A *big.Int, P *big.Int) point.Point {
	mode := newCurveMode(A, P)
	return fromJacobian(jacobianAdd(toJacobian(p), toJacobian(q), mode), P)
}

// MultiplyAndAdd computes n1*p1 + n2*p2 using Shamir's trick (simultaneous double-and-add).
// Not constant-time -- use only with public scalars (e.g. verification).
func MultiplyAndAdd(p1 point.Point, n1 *big.Int, p2 point.Point, n2 *big.Int, N *big.Int, A *big.Int, P *big.Int) point.Point {
	mode := newCurveMode(A, P)
	return fromJacobian(
		shamirMultiply(
			toJacobian(p1), n1,
			toJacobian(p2), n2,
			N, mode,
		), P,
	)
}

// MultiplyGeneratorParams bundles the curve parameters required for fast
// fixed-base scalar multiplication. It is used internally by MultiplyGenerator
// so this package does not need to import the curve package (which would
// create an import cycle).
type MultiplyGeneratorParams struct {
	G          point.Point
	A          *big.Int
	P          *big.Int
	N          *big.Int
	NBitLength int
	Cache      *GeneratorCache
}

// MultiplyGenerator computes n*G using a precomputed window table
// (2^4-ary method). Roughly 2-3x faster than variable-base multiplication
// because doublings stay cheap and additions use pre-stored multiples of G.
func MultiplyGenerator(params MultiplyGeneratorParams, n *big.Int) point.Point {
	if n.Sign() < 0 || n.Cmp(params.N) >= 0 {
		n = new(big.Int).Mod(n, params.N)
	}
	if n.Sign() == 0 {
		return point.Point{X: big.NewInt(0), Y: big.NewInt(0), Z: big.NewInt(0)}
	}

	mode := newCurveMode(params.A, params.P)
	table := generatorTable(params, mode)
	w := generatorWindowBits
	mask := uint((1 << w) - 1)

	// Jacobian infinity: y=0 triggers the early-return in jacobianAdd.
	r := point.Point{X: big.NewInt(0), Y: big.NewInt(0), Z: big.NewInt(1)}
	startBit := ((params.NBitLength - 1) / w) * w
	for bit := startBit; bit >= 0; bit -= w {
		for i := 0; i < w; i++ {
			r = jacobianDouble(r, mode)
		}
		window := extractWindow(n, bit, w, mask)
		if window != 0 {
			r = jacobianAdd(r, table[window], mode)
		}
	}
	return fromJacobian(r, params.P)
}

func extractWindow(n *big.Int, bit int, w int, mask uint) uint {
	var window uint
	for i := 0; i < w; i++ {
		window |= uint(n.Bit(bit+i)) << uint(i)
	}
	return window & mask
}

func generatorTable(params MultiplyGeneratorParams, mode curveMode) []point.Point {
	cache := params.Cache
	cache.Once.Do(func() {
		w := generatorWindowBits
		size := 1 << w
		table := make([]point.Point, size)
		// table[0] = point at infinity (Jacobian, y=0 triggers early-return)
		table[0] = point.Point{X: big.NewInt(0), Y: big.NewInt(0), Z: big.NewInt(1)}
		G := point.Point{
			X: new(big.Int).Set(params.G.X),
			Y: new(big.Int).Set(params.G.Y),
			Z: big.NewInt(1),
		}
		table[1] = G
		for i := 2; i < size; i++ {
			table[i] = jacobianAdd(table[i-1], G, mode)
		}
		cache.Table = table
	})
	return cache.Table
}

// Inv computes modular inverse via the extended Euclidean algorithm
// (big.Int.ModInverse). Roughly 2-3x faster than Fermat's little theorem
// for 256-bit operands.
//
// Panics when x has no inverse mod n (i.e. x is 0 mod n).
func Inv(x *big.Int, n *big.Int) *big.Int {
	if x.Sign() == 0 {
		return big.NewInt(0)
	}
	r := new(big.Int).ModInverse(x, n)
	if r == nil {
		// x shares a factor with n -- no inverse exists. For ECDSA curve
		// parameters n is prime so this only happens when x ≡ 0 (mod n).
		panic("0 has no modular inverse")
	}
	return r
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

// jacobianDouble doubles a point in Jacobian coordinates. Uses curve-specific
// shortcuts when the coefficient A is 0 (secp256k1) or A ≡ -3 (prime256v1).
func jacobianDouble(p point.Point, mode curveMode) point.Point {
	if p.Y.Sign() == 0 {
		return point.Point{X: big.NewInt(0), Y: big.NewInt(0), Z: big.NewInt(0)}
	}

	P := mode.P
	px, py, pz := p.X, p.Y, p.Z

	ysq := new(big.Int).Mul(py, py)
	ysq.Mod(ysq, P)

	S := new(big.Int).Mul(big.NewInt(4), px)
	S.Mul(S, ysq).Mod(S, P)

	pz2 := new(big.Int).Mul(pz, pz)
	pz2.Mod(pz2, P)

	var M *big.Int
	switch {
	case mode.aIsZero:
		// A = 0 (secp256k1): M = 3 * px^2
		M = new(big.Int).Mul(px, px)
		M.Mul(M, big.NewInt(3)).Mod(M, P)
	case mode.aIsMin3:
		// A = -3 (prime256v1): M = 3 * (px - pz^2) * (px + pz^2)
		diff := new(big.Int).Sub(px, pz2)
		sum := new(big.Int).Add(px, pz2)
		M = new(big.Int).Mul(diff, sum)
		M.Mul(M, big.NewInt(3)).Mod(M, P)
	default:
		// Generic: M = 3 * px^2 + A * pz^4
		M = new(big.Int).Mul(px, px)
		M.Mul(M, big.NewInt(3))
		tmp := new(big.Int).Mul(mode.A, pz2)
		tmp.Mul(tmp, pz2)
		M.Add(M, tmp).Mod(M, P)
	}

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
func jacobianAdd(p point.Point, q point.Point, mode curveMode) point.Point {
	if p.Y.Sign() == 0 {
		return q
	}
	if q.Y.Sign() == 0 {
		return p
	}

	P := mode.P
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
		return jacobianDouble(p, mode)
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
func jacobianMultiply(p point.Point, n *big.Int, N *big.Int, mode curveMode) point.Point {
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
			r1 = jacobianAdd(r0, r1, mode)
			r0 = jacobianDouble(r0, mode)
		} else {
			r0 = jacobianAdd(r0, r1, mode)
			r1 = jacobianDouble(r1, mode)
		}
	}

	return r0
}

// shamirMultiply computes n1*p1 + n2*p2 using Shamir's trick (simultaneous double-and-add).
// Not constant-time -- use only with public scalars (e.g. verification).
func shamirMultiply(jp1 point.Point, n1 *big.Int, jp2 point.Point, n2 *big.Int, N *big.Int, mode curveMode) point.Point {
	if n1.Sign() < 0 || n1.Cmp(N) >= 0 {
		n1 = new(big.Int).Mod(n1, N)
	}
	if n2.Sign() < 0 || n2.Cmp(N) >= 0 {
		n2 = new(big.Int).Mod(n2, N)
	}

	jp1p2 := jacobianAdd(jp1, jp2, mode)

	l := n1.BitLen()
	if n2.BitLen() > l {
		l = n2.BitLen()
	}

	r := point.Point{X: big.NewInt(0), Y: big.NewInt(0), Z: big.NewInt(1)}

	for i := l - 1; i >= 0; i-- {
		r = jacobianDouble(r, mode)
		b1 := n1.Bit(i)
		b2 := n2.Bit(i)
		if b1 == 1 {
			if b2 == 1 {
				r = jacobianAdd(r, jp1p2, mode)
			} else {
				r = jacobianAdd(r, jp1, mode)
			}
		} else if b2 == 1 {
			r = jacobianAdd(r, jp2, mode)
		}
	}

	return r
}
