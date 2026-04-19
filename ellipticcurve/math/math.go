package math

import (
	"math/big"
	"sync"

	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/point"
)

// one is a shared read-only *big.Int used for "is this value 1?" comparisons.
// big.Int's Cmp does not mutate its operand, so sharing is safe.
var one = big.NewInt(1)

// GeneratorCache holds the precomputed affine table [G, 2G, 4G, ...,
// 2^nBitLength * G] used by the NAF fixed-base scalar multiplication. It
// is populated lazily on the first call to MultiplyGenerator and shared
// across copies of CurveFp via pointer.
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

// MultiplyGenerator computes n*G using a precomputed affine table of
// powers-of-two multiples of G and the width-2 NAF of n. Every non-zero NAF
// digit triggers one mixed add and zero doublings, trading the ~256
// doublings of a windowed method for ~86 adds on average -- a large net
// reduction in field multiplications for 256-bit scalars.
func MultiplyGenerator(params MultiplyGeneratorParams, n *big.Int) point.Point {
	if n.Sign() < 0 || n.Cmp(params.N) >= 0 {
		n = new(big.Int).Mod(n, params.N)
	}
	if n.Sign() == 0 {
		return point.Point{X: big.NewInt(0), Y: big.NewInt(0), Z: big.NewInt(0)}
	}

	mode := newCurveMode(params.A, params.P)
	table := generatorTable(params, mode)
	P := params.P

	// Work on a fresh copy of n since we mutate it bit-by-bit.
	k := new(big.Int).Set(n)
	r := point.Point{X: big.NewInt(0), Y: big.NewInt(0), Z: big.NewInt(1)}
	i := 0
	for k.Sign() > 0 {
		if k.Bit(0) == 1 {
			// digit = 2 - (k & 3), yielding +1 or -1.
			low2 := int(k.Bit(0)) | (int(k.Bit(1)) << 1)
			digit := 2 - low2
			if digit == 1 {
				k.Sub(k, one)
				r = jacobianAdd(r, table[i], mode)
			} else {
				k.Add(k, one)
				g := table[i]
				neg := point.Point{
					X: new(big.Int).Set(g.X),
					Y: new(big.Int).Sub(P, g.Y),
					Z: new(big.Int).Set(g.Z),
				}
				r = jacobianAdd(r, neg, mode)
			}
		}
		k.Rsh(k, 1)
		i++
	}
	return fromJacobian(r, params.P)
}

func generatorTable(params MultiplyGeneratorParams, mode curveMode) []point.Point {
	cache := params.Cache
	cache.Once.Do(func() {
		P := params.P
		// NAF of an nBitLength-bit scalar can be up to nBitLength+1 digits.
		size := params.NBitLength + 1
		table := make([]point.Point, 0, size)
		current := point.Point{
			X: new(big.Int).Set(params.G.X),
			Y: new(big.Int).Set(params.G.Y),
			Z: big.NewInt(1),
		}
		table = append(table, current)
		for j := 0; j < params.NBitLength; j++ {
			doubled := jacobianDouble(current, mode)
			if doubled.Y.Sign() == 0 {
				current = doubled
			} else {
				zInv := Inv(doubled.Z, P)
				zInv2 := new(big.Int).Mul(zInv, zInv)
				zInv2.Mod(zInv2, P)
				zInv3 := new(big.Int).Mul(zInv2, zInv)
				zInv3.Mod(zInv3, P)
				x := new(big.Int).Mul(doubled.X, zInv2)
				x.Mod(x, P)
				y := new(big.Int).Mul(doubled.Y, zInv3)
				y.Mod(y, P)
				current = point.Point{X: x, Y: y, Z: big.NewInt(1)}
			}
			table = append(table, current)
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

// jacobianAdd adds two points in Jacobian coordinates. When qz == 1 (q is
// affine) it takes a mixed-add fast path that saves four field multiplications
// per call (no qz^2, simplified U1, S1, and nz).
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

	pz2 := new(big.Int).Mul(pz, pz)
	pz2.Mod(pz2, P)

	U2 := new(big.Int).Mul(qx, pz2)
	U2.Mod(U2, P)
	S2 := new(big.Int).Mul(qy, pz2)
	S2.Mul(S2, pz).Mod(S2, P)

	qzIsOne := qz.Sign() != 0 && qz.Cmp(one) == 0

	var U1, S1 *big.Int
	if qzIsOne {
		// Mixed affine+Jacobian add: qz^2 = qz^3 = 1 saves four multiplications.
		U1 = new(big.Int).Set(px)
		S1 = new(big.Int).Set(py)
	} else {
		qz2 := new(big.Int).Mul(qz, qz)
		qz2.Mod(qz2, P)
		U1 = new(big.Int).Mul(px, qz2)
		U1.Mod(U1, P)
		S1 = new(big.Int).Mul(py, qz2)
		S1.Mul(S1, qz).Mod(S1, P)
	}

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

	var nz *big.Int
	if qzIsOne {
		nz = new(big.Int).Mul(H, pz)
		nz.Mod(nz, P)
	} else {
		nz = new(big.Int).Mul(H, pz)
		nz.Mul(nz, qz).Mod(nz, P)
	}

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

// shamirMultiply computes n1*p1 + n2*p2 using Shamir's trick with Joint
// Sparse Form (Solinas 2001). JSF picks signed digits in {-1, 0, 1} so at
// most ~l/2 digit pairs are non-zero, versus ~3l/4 for the raw binary form.
// Not constant-time -- use only with public scalars (e.g. verification).
func shamirMultiply(jp1 point.Point, n1 *big.Int, jp2 point.Point, n2 *big.Int, N *big.Int, mode curveMode) point.Point {
	if n1.Sign() < 0 || n1.Cmp(N) >= 0 {
		n1 = new(big.Int).Mod(n1, N)
	}
	if n2.Sign() < 0 || n2.Cmp(N) >= 0 {
		n2 = new(big.Int).Mod(n2, N)
	}

	if n1.Sign() == 0 && n2.Sign() == 0 {
		return point.Point{X: big.NewInt(0), Y: big.NewInt(0), Z: big.NewInt(1)}
	}

	P := mode.P
	neg := func(pt point.Point) point.Point {
		var ny *big.Int
		if pt.Y.Sign() == 0 {
			ny = big.NewInt(0)
		} else {
			ny = new(big.Int).Sub(P, pt.Y)
		}
		return point.Point{
			X: new(big.Int).Set(pt.X),
			Y: ny,
			Z: new(big.Int).Set(pt.Z),
		}
	}

	jp1p2 := jacobianAdd(jp1, jp2, mode)
	jp1mp2 := jacobianAdd(jp1, neg(jp2), mode)
	negJp1 := neg(jp1)
	negJp2 := neg(jp2)
	negJp1p2 := neg(jp1p2)
	negJp1mp2 := neg(jp1mp2)

	digits := jsfDigits(n1, n2)
	r := point.Point{X: big.NewInt(0), Y: big.NewInt(0), Z: big.NewInt(1)}
	for _, d := range digits {
		r = jacobianDouble(r, mode)
		u0, u1 := d[0], d[1]
		if u0 == 0 && u1 == 0 {
			continue
		}
		var addend point.Point
		switch {
		case u0 == 1 && u1 == 0:
			addend = jp1
		case u0 == -1 && u1 == 0:
			addend = negJp1
		case u0 == 0 && u1 == 1:
			addend = jp2
		case u0 == 0 && u1 == -1:
			addend = negJp2
		case u0 == 1 && u1 == 1:
			addend = jp1p2
		case u0 == -1 && u1 == -1:
			addend = negJp1p2
		case u0 == 1 && u1 == -1:
			addend = jp1mp2
		case u0 == -1 && u1 == 1:
			addend = negJp1mp2
		}
		r = jacobianAdd(r, addend, mode)
	}

	return r
}

// jsfDigits returns the Joint Sparse Form of (k0, k1): list of signed-digit
// pairs [u0, u1] in {-1, 0, 1}, ordered MSB-first. At most one of any two
// consecutive pairs is non-zero, giving density ~1/2 instead of ~3/4 from
// raw binary.
func jsfDigits(k0 *big.Int, k1 *big.Int) [][2]int {
	k0 = new(big.Int).Set(k0)
	k1 = new(big.Int).Set(k1)
	d0 := 0
	d1 := 0
	digits := make([][2]int, 0, k0.BitLen()+2)
	for {
		// loop while (k0 + d0) != 0 or (k1 + d1) != 0
		if k0.Sign() == 0 && d0 == 0 && k1.Sign() == 0 && d1 == 0 {
			break
		}
		// a0 = k0 + d0 (only low 3 bits matter)
		a0Low := int(k0.Bit(0)) | (int(k0.Bit(1)) << 1) | (int(k0.Bit(2)) << 2)
		a0Low = (a0Low + d0) & 7
		a1Low := int(k1.Bit(0)) | (int(k1.Bit(1)) << 1) | (int(k1.Bit(2)) << 2)
		a1Low = (a1Low + d1) & 7

		var u0 int
		if a0Low&1 == 1 {
			if a0Low&3 == 1 {
				u0 = 1
			} else {
				u0 = -1
			}
			if (a0Low&7 == 3 || a0Low&7 == 5) && a1Low&3 == 2 {
				u0 = -u0
			}
		}
		var u1 int
		if a1Low&1 == 1 {
			if a1Low&3 == 1 {
				u1 = 1
			} else {
				u1 = -1
			}
			if (a1Low&7 == 3 || a1Low&7 == 5) && a0Low&3 == 2 {
				u1 = -u1
			}
		}
		digits = append(digits, [2]int{u0, u1})
		if 2*d0 == 1+u0 {
			d0 = 1 - d0
		}
		if 2*d1 == 1+u1 {
			d1 = 1 - d1
		}
		k0.Rsh(k0, 1)
		k1.Rsh(k1, 1)
	}
	// reverse
	for i, j := 0, len(digits)-1; i < j; i, j = i+1, j-1 {
		digits[i], digits[j] = digits[j], digits[i]
	}
	return digits
}
