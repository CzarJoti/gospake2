package ed25519

import (
	"filippo.io/edwards25519"
)

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

type Point = edwards25519.Point

type Scalar = edwards25519.Scalar
