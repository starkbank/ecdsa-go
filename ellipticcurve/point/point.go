package point

import (
	"math/big"
)

type Point struct {
	X *big.Int
	Y *big.Int
	Z *big.Int
}

func (obj Point) IsAtInfinity() bool {
	return obj.Y.Cmp(big.NewInt(0)) == 0
}
