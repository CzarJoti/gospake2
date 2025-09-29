package ed25519

import (
	"encoding/hex"

	"filippo.io/edwards25519"
)

const (
	M_HEX = "d048032c6ea0b6d697ddc2e86bda85a33adac920f1bf18e1b0c6d166a5cecdaf"
	N_HEX = "d3bfb518f44f3430f29d0c92af503865a1ed3281dc69b35dd868ba85f886c4ab"
)

var mpnt, _ = hex.DecodeString(M_HEX)
var npnt, _ = hex.DecodeString(N_HEX)

type Curve struct {
}

func (c *Curve) NewGeneratorPoint() *edwards25519.Point {
	return edwards25519.NewGeneratorPoint()
}

func (c *Curve) NewIdentityPoint() *edwards25519.Point {
	return edwards25519.NewIdentityPoint()
}

func (c *Curve) NewPoint() *edwards25519.Point {
	return new(edwards25519.Point)
}

func (c *Curve) NewScalar() *edwards25519.Scalar {
	return edwards25519.NewScalar()
}

func (c *Curve) NewMPoint() *edwards25519.Point {
	p, _ := c.NewPoint().SetBytes(mpnt)
	return p
}

func (c *Curve) NewNPoint() *edwards25519.Point {
	p, _ := c.NewPoint().SetBytes(npnt)
	return p
}

type Point = edwards25519.Point

type Scalar = edwards25519.Scalar
