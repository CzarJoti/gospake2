package gospake2

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
	"io"

	"github.com/ValiantChip/gospake2/internal/ed25519"
)

var (
	ErrAlreadyStarted     = errors.New("instance has already been started")
	ErrNotStarted         = errors.New("instance has not been started")
	ErrAlreadyFinished    = errors.New("instance has already been finished")
	ErrNotFinished        = errors.New("instance has not been finished")
	ErrVerificationFailed = errors.New("verification failed")
)

// DEFAULT_SUITE is the default ciphersuite for use in Spake2
// Note: sha512 is not Memory-Hard and is not recommended by rfc9382
var DEFAULT_SUITE = CipherSuite[*ed25519.Scalar, *ed25519.Point, *ed25519.Curve]{
	Group:        new(ed25519.Curve),
	Hash:         sha256.New,
	PasswordHash: sha512.New,
	Kdf:          hkdf.Key[hash.Hash],
	Mac:          hmac.New,
}

type spake2Symetric[S Scalar[S], W Point[W, S], G Group[W, S]] struct {
	p        protocol[S, W, G]
	A        string
	B        string
	started  bool
	finished bool
	w        S
	pA       W
	pB       W
	cA       []byte
	cB       []byte
	rand     io.Reader
}

// represents A in the Spake2 protocol
type Spake2A[S Scalar[S], W Point[W, S], G Group[W, S]] struct {
	spake2Symetric[S, W, G]
	x S
}

// Creates a new instance of A
// pw is a slice of bytes known to both A and B
// A and B are strings that are shared between A and B
func NewA[S Scalar[S], W Point[W, S], G Group[W, S]](pw []byte, A, B string, rand io.Reader, c CipherSuite[S, W, G]) (*Spake2A[S, W, G], error) {
	s, err := newSpake2(pw, A, B, rand, c)
	if err != nil {
		return nil, err
	}
	return &Spake2A[S, W, G]{
		spake2Symetric: s,
	}, nil
}

// Starts the protocol for A and returns the byte slice representation of pA
// If Start() has already been called on this instance ofA ErrAlreadyStarted will be returned
func (s *Spake2A[S, W, G]) Start() ([]byte, error) {
	if s.started {
		return nil, ErrAlreadyStarted
	}
	x := s.p.randomScalar(s.rand)
	s.x = x

	pA := s.p.generate_pA(s.w, x)
	s.pA = pA

	s.started = true
	return pA.Bytes(), nil
}

// Returns thre shared secret key and the confirmation message from the Spake2 protocol
// Key is the shared secret returned from the protocol
// Cmsg is the confirmation message to send to B for key confirmation
// Confirmation if the message to be compared to the message recieved from B for key confirmation
func (s *Spake2A[S, W, G]) Finish(msg []byte) (key, cmsg []byte, err error) {
	if s.finished {
		return nil, nil, ErrAlreadyFinished
	}

	if !s.started {
		return nil, nil, ErrNotStarted
	}

	pB, err := s.p.g.NewPoint().SetBytes(msg)
	if err != nil {
		return
	}

	s.pB = pB

	K := s.p.aGenerateK(pB, s.w, s.x)
	var cB []byte
	key, cmsg, cB = s.p.generateSecrets(s.A, s.B, s.pA, pB, K, s.w)

	s.cB = cB

	s.finished = true
	return
}

// Verifies the confirmation message from A
// If the verification fails ErrVerificationFailed will be returned
// If the instance has not been finished ErrNotFinished will be returned
func (s *Spake2A[S, W, G]) Verify(msg []byte) error {
	if !s.finished {
		return ErrNotFinished
	}

	if b := hmac.Equal(s.cB, msg); !b {
		return ErrVerificationFailed
	}
	return nil
}

// Represents B in the Spake2 protocol
type Spake2B[S Scalar[S], W Point[W, S], G Group[W, S]] struct {
	spake2Symetric[S, W, G]
	y S
}

// Creates a new instance of B
// pw is a slice of bytes known to both A and B
// A and B are strings that are shared between A and B
func NewB[S Scalar[S], W Point[W, S], G Group[W, S]](pw []byte, A string, B string, rand io.Reader, c CipherSuite[S, W, G]) (*Spake2B[S, W, G], error) {
	s, err := newSpake2(pw, A, B, rand, c)
	if err != nil {
		return nil, err
	}
	return &Spake2B[S, W, G]{spake2Symetric: s}, nil
}

func newSpake2[S Scalar[S], W Point[W, S], G Group[W, S]](pw []byte, A string, B string, rand io.Reader, c CipherSuite[S, W, G]) (spake2Symetric[S, W, G], error) {
	s := spake2Symetric[S, W, G]{}
	s.p = newProtocol(c)
	w, err := s.p.generate_w(pw)
	if err != nil {
		return s, err
	}
	s.w = w
	s.A = A
	s.B = B
	s.rand = rand
	return s, nil
}

// Starts the protocol for B and returns the byte slice representation of pA
// If Start() has already been called on this instance of B ErrAlreadyStarted will be returned
func (s *Spake2B[S, W, G]) Start() ([]byte, error) {
	if s.started {
		return nil, ErrAlreadyStarted
	}

	y := s.p.randomScalar(s.rand)
	s.y = y

	pB := s.p.generate_pB(s.w, y)
	s.pB = pB

	s.started = true
	return pB.Bytes(), nil
}

// Returns thre shared secret key and the confirmation message from the Spake2 protocol
// Key is the shared secret returned from the protocol
// Cmsg is the confirmation message to send to A for key confirmation
// Confirmation if the message to be compared to the message recieved from A for key confirmation
func (s *Spake2B[S, W, G]) Finish(msg []byte) (key, cmsg []byte, err error) {
	if s.finished {
		return nil, nil, ErrAlreadyFinished
	}

	if !s.started {
		return nil, nil, ErrNotStarted
	}

	pA, err := s.p.g.NewPoint().SetBytes(msg)
	if err != nil {
		return
	}

	K := s.p.bGenerateK(pA, s.w, s.y)

	var cA []byte
	key, cA, cmsg = s.p.generateSecrets(s.A, s.B, pA, s.pB, K, s.w)

	s.cA = cA

	s.finished = true
	return
}

// Verifies the confirmation message from A
// If the verification fails ErrVerificationFailed will be returned
// If the instance has not been finished ErrNotFinished will be returned
func (s *Spake2B[S, W, G]) Verify(msg []byte) error {
	if !s.finished {
		return ErrNotFinished
	}

	if b := hmac.Equal(s.cA, msg); !b {
		return ErrVerificationFailed
	}
	return nil
}
