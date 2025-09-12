package gospake2

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"io"
)

const (
	M_HEX = "d048032c6ea0b6d697ddc2e86bda85a33adac920f1bf18e1b0c6d166a5cecdaf"
	N_HEX = "d3bfb518f44f3430f29d0c92af503865a1ed3281dc69b35dd868ba85f886c4ab"
)

type CipherSuite[S Scalar[S], W Point[W, S], G Group[W, S]] struct {
	Group        G
	Hash         func() hash.Hash
	PasswordHash func() hash.Hash
	Kdf          func(func() hash.Hash, []byte, []byte, string, int) ([]byte, error)
	Mac          func(func() hash.Hash, []byte) hash.Hash
}

func NewCipherSuite[S Scalar[S], W Point[W, S], G Group[W, S]](
	group G,
	hash func() hash.Hash,
	passwordHash func() hash.Hash,
	kdf func(func() hash.Hash, []byte, []byte, string, int) ([]byte, error),
	mac func(func() hash.Hash, []byte) hash.Hash,
) CipherSuite[S, W, G] {
	return CipherSuite[S, W, G]{
		Group:        group,
		Hash:         hash,
		PasswordHash: passwordHash,
		Kdf:          kdf,
		Mac:          mac,
	}
}

type protocol[S Scalar[S], W Point[W, S], G Group[W, S]] struct {
	g      G
	hsh    func() hash.Hash
	pwdhsh func() hash.Hash
	kdf    func(func() hash.Hash, []byte, []byte, string, int) ([]byte, error)
	mac    func(func() hash.Hash, []byte) hash.Hash
	M      W
	N      W
	P      W
}

func newProtocol[S Scalar[S], W Point[W, S], G Group[W, S]](c CipherSuite[S, W, G]) protocol[S, W, G] {
	p := protocol[S, W, G]{}
	p.g = c.Group
	p.hsh = c.Hash
	p.pwdhsh = c.PasswordHash
	p.kdf = c.Kdf
	p.mac = c.Mac
	mpnt, _ := hex.DecodeString(M_HEX)
	npnt, _ := hex.DecodeString(N_HEX)

	M, _ := p.g.NewPoint().SetBytes(mpnt)
	N, _ := p.g.NewPoint().SetBytes(npnt)
	P := p.g.NewGeneratorPoint()

	p.M = M
	p.N = N
	p.P = P
	return p
}

func (p *protocol[S, W, G]) generate_w(pw []byte) (w S, err error) {
	h := p.pwdhsh()
	_, err = h.Write(pw)
	if err != nil {
		return
	}

	q := h.Sum(nil)
	w, err = p.g.NewScalar().SetUniformBytes(q[:])
	return
}

func (p *protocol[S, W, G]) generateK(b W, w, t S, Q W) (K W) {
	K = p.g.NewPoint()

	temp := p.g.NewPoint()
	temp = temp.ScalarMult(w, Q)
	K = K.Subtract(b, temp)
	K = K.ScalarMult(t, K)
	K = K.MultByCofactor(K)
	return
}

func (p *protocol[S, W, G]) generate_pA(w, x S) (pA W) {
	X := p.g.NewPoint()
	X = X.ScalarMult(x, p.P)

	pA = p.g.NewPoint()
	pA = pA.ScalarMult(w, p.M)
	pA = pA.Add(pA, X)
	return
}

func (p *protocol[S, W, G]) generate_pB(w, y S) (pB W) {
	Y := p.g.NewPoint()
	Y = Y.ScalarMult(y, p.P)

	pB = p.g.NewPoint()
	pB = pB.ScalarMult(w, p.N)
	pB = pB.Add(pB, Y)
	return
}

func (p *protocol[S, W, G]) aGenerateK(pB W, w, x S) (K W) {
	K = p.generateK(pB, w, x, p.N)
	return
}

func (p *protocol[S, W, G]) bGenerateK(pA W, w, y S) (K W) {
	K = p.generateK(pA, w, y, p.M)
	return
}

func (p *protocol[S, W, G]) generateSecrets(A, B string, pA, pB, K W, w S) (Ke, cA, cB []byte) {
	TT := new(bytes.Buffer)
	writeVal(TT, []byte(A))
	writeVal(TT, []byte(B))
	writeVal(TT, pA.Bytes())
	writeVal(TT, pB.Bytes())
	writeVal(TT, K.Bytes())
	writeVal(TT, w.Bytes())

	h := p.hsh()
	h.Write(TT.Bytes())
	Kpart := h.Sum(nil)
	Ke = Kpart[:16]
	Ka := Kpart[16:]

	KcPart, err := p.kdf(p.hsh, Ka, nil, "ConfirmationKeys", 32)
	if err != nil {
		panic(err)
	}

	KcA := KcPart[:16]
	KcB := KcPart[16:]

	cA = p.mac(p.hsh, KcA).Sum(nil)
	cB = p.mac(p.hsh, KcB).Sum(nil)

	return
}

func (p *protocol[S, W, G]) randomScalar(r io.Reader) S {
	b := make([]byte, 64)
	r.Read(b)
	s, _ := p.g.NewScalar().SetUniformBytes(b)
	return s
}

func writeVal(w io.Writer, v []byte) {
	binary.Write(w, binary.LittleEndian, uint64(len(v)))
	w.Write(v)
}
