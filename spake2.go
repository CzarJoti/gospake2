package gospake2

import (
	"errors"

	"filippo.io/edwards25519"
	"github.com/ValiantChip/GoSpake2/lib/protocol"
)

var ErrAlreadyStarted = errors.New("instance has already been started")

type spake2Symetric struct {
	A       string
	B       string
	started bool
	pw      []byte
	w       *edwards25519.Scalar
	pA      *edwards25519.Point
	pB      *edwards25519.Point
	k       *edwards25519.Point

	ke, cA, cB []byte
}

type Spake2A struct {
	spake2Symetric
}

func NewA(pw []byte, A, B string) *Spake2A {
	ret := new(Spake2A)

	ret.pw = pw

	return ret
}

func (s *Spake2A) Start() ([]byte, error) {
	if s.started {
		return nil, ErrAlreadyStarted
	}
	s.started = true
	x := protocol.RandomScalar()
	w, err := protocol.Generate_w(s.pw)
	if err != nil {
		return nil, err
	}

	pA := protocol.Generate_pA(w, x)

	return pA.Bytes(), nil
}

func (s *Spake2A) Finish(msg []byte) (key, confirmation []byte, err error) {
	pB, err := new(edwards25519.Point).SetBytes(msg)
	if err != nil {
		return
	}

	key, confirmation, _ = protocol.GenerateSecrets(s.A, s.B, s.pA, pB, s.k, s.w)

	return
}

type Spake2B struct {
	spake2Symetric
}

func NewB(pw []byte) *Spake2B {
	ret := new(Spake2B)

	ret.pw = pw

	return ret
}

func (s *Spake2B) Start() ([]byte, error) {
	if s.started {
		return nil, ErrAlreadyStarted
	}

	s.started = true
	y := protocol.RandomScalar()
	w, err := protocol.Generate_w(s.pw)
	if err != nil {
		return nil, err
	}

	pB := protocol.Generate_pB(w, y)

	return pB.Bytes(), nil
}

func (s *Spake2B) Finish(msg []byte) (key, confirmation []byte, err error) {
	pA, err := new(edwards25519.Point).SetBytes(msg)
	if err != nil {
		return
	}

	key, _, confirmation = protocol.GenerateSecrets(s.A, s.B, pA, s.pB, s.k, s.w)

	return
}
