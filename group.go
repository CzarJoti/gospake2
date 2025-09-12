package gospake2

type Group[P Point[P, S], S Scalar[S]] interface {
	NewGeneratorPoint() P
	NewIdentityPoint() P
	NewPoint() P
	NewScalar() S
}

type Point[P any, S any] interface {
	Add(p, q P) P
	Subtract(p, q P) P
	Bytes() []byte
	MultByCofactor(p P) P
	ScalarMult(x S, p P) P
	ScalarBaseMult(x S) P
	Set(p P) P
	SetBytes(x []byte) (P, error)
	Equal(p P) int
}

type Scalar[S any] interface {
	Add(x, y S) S
	Subtract(x, y S) S
	Bytes() []byte
	Equal(x S) int
	Invert(x S) S
	Multiply(x, y S) S
	Negate(x S) S
	Set(x S) S
	SetUniformBytes(x []byte) (S, error)
}
