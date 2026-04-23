package point

import (
	"fmt"
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

func (obj Point) String() string {
	return fmt.Sprintf("(%s, %s, %s)", obj.X.String(), obj.Y.String(), obj.Z.String())
}
