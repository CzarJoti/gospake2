package gospake2

import (
	"crypto/hmac"
	"errors"
	"io"

	"filippo.io/edwards25519"
	"github.com/ValiantChip/GoSpake2/lib/protocol"
)

var ErrAlreadyStarted = errors.New("instance has already been started")
var ErrNotStarted = errors.New("instance has not been started")
var ErrAlreadyFinished = errors.New("instance has already been finished")
var ErrNotFinished = errors.New("instance has not been finished")

type spake2Symetric struct {
	A        string
	B        string
	started  bool
	finished bool
	pw       []byte
	w        *edwards25519.Scalar
	pA       *edwards25519.Point
	pB       *edwards25519.Point
	cA       []byte
	cB       []byte
	rand     io.Reader
}

// represents A in the Spake2 protocol
type Spake2A struct {
	spake2Symetric
	x *edwards25519.Scalar
}

// Creates a new instance of A
// pw is a slice of bytes known to both A and B
// A and B are strings that are shared between A and B
// is a
func NewA(pw []byte, A, B string, rand io.Reader) *Spake2A {
	return &Spake2A{
		spake2Symetric: newSpake2(pw, A, B, rand),
	}
}

// Starts the protocol for A and returns the byte slice representation of pA
// If Start() has already been called on this instance ofA ErrAlreadyStarted will be returned
func (s *Spake2A) Start() ([]byte, error) {
	if s.started {
		return nil, ErrAlreadyStarted
	}
	x := protocol.RandomScalar(s.rand)
	s.x = x
	w, err := protocol.Generate_w(s.pw)
	if err != nil {
		return nil, err
	}
	s.w = w

	pA := protocol.Generate_pA(w, x)
	s.pA = pA

	s.started = true
	return pA.Bytes(), nil
}

// Returns thre shared secret key and the confirmation message from the Spake2 protocol
// Key is the shared secret returned from the protocol
// Cmsg is the confirmation message to send to B for key confirmation
// Confirmation if the message to be compared to the message recieved from B for key confirmation
func (s *Spake2A) Finish(msg []byte) (key, cmsg []byte, err error) {
	if s.finished {
		return nil, nil, ErrAlreadyFinished
	}

	if !s.started {
		return nil, nil, ErrNotStarted
	}
	pB, err := new(edwards25519.Point).SetBytes(msg)
	if err != nil {
		return
	}

	K := protocol.AGenerateK(s.pA, pB, s.w, s.x)
	var cB []byte
	key, cmsg, cB = protocol.GenerateSecrets(s.A, s.B, s.pA, pB, K, s.w)

	s.cB = cB

	s.finished = true
	return
}

func (s *Spake2A) Verify(msg []byte) (bool, error) {
	if !s.finished {
		return false, ErrNotFinished
	}
	b := hmac.Equal(s.cB, msg)
	return b, nil
}

// Represents B in the Spake2 protocol
type Spake2B struct {
	spake2Symetric
	y *edwards25519.Scalar
}

// Creates a new instance of B
// pw is a slice of bytes known to both A and B
// A and B are strings that are shared between A and B
func NewB(pw []byte, A string, B string, rand io.Reader) *Spake2B {
	return &Spake2B{
		spake2Symetric: newSpake2(pw, A, B, rand),
	}
}

func newSpake2(pw []byte, A string, B string, rand io.Reader) spake2Symetric {
	return spake2Symetric{
		pw:   pw,
		A:    A,
		B:    B,
		rand: rand,
	}
}

// Starts the protocol for B and returns the byte slice representation of pA
// If Start() has already been called on this instance of B ErrAlreadyStarted will be returned
func (s *Spake2B) Start() ([]byte, error) {
	if s.started {
		return nil, ErrAlreadyStarted
	}

	y := protocol.RandomScalar(s.rand)
	s.y = y
	w, err := protocol.Generate_w(s.pw)
	if err != nil {
		return nil, err
	}

	s.w = w

	pB := protocol.Generate_pB(w, y)
	s.pB = pB

	s.started = true
	return pB.Bytes(), nil
}

// Returns thre shared secret key and the confirmation message from the Spake2 protocol
// Key is the shared secret returned from the protocol
// Cmsg is the confirmation message to send to A for key confirmation
// Confirmation if the message to be compared to the message recieved from A for key confirmation
func (s *Spake2B) Finish(msg []byte) (key, cmsg []byte, err error) {
	if s.finished {
		return nil, nil, ErrAlreadyFinished
	}

	if !s.started {
		return nil, nil, ErrNotStarted
	}

	pA, err := new(edwards25519.Point).SetBytes(msg)
	if err != nil {
		return
	}

	K := protocol.BGenerateK(pA, s.pB, s.w, s.y)

	var cA []byte
	key, cA, cmsg = protocol.GenerateSecrets(s.A, s.B, pA, s.pB, K, s.w)

	s.cA = cA

	s.finished = true
	return
}

func (s *Spake2B) Verify(msg []byte) (bool, error) {
	if !s.finished {
		return false, ErrNotFinished
	}
	b := hmac.Equal(s.cA, msg)
	return b, nil
}
