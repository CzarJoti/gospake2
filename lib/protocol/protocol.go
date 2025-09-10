package protocol

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"io"

	"filippo.io/edwards25519"
)

var mpnt, _ = hex.DecodeString("d048032c6ea0b6d697ddc2e86bda85a33adac920f1bf18e1b0c6d166a5cecdaf")
var npnt, _ = hex.DecodeString("d3bfb518f44f3430f29d0c92af503865a1ed3281dc69b35dd868ba85f886c4ab")

var M, _ = new(edwards25519.Point).SetBytes(mpnt)
var N, _ = new(edwards25519.Point).SetBytes(npnt)
var P = edwards25519.NewGeneratorPoint()

func Generate_w(pw []byte) (w *edwards25519.Scalar, err error) {
	q := sha512.Sum512(pw)
	w, err = edwards25519.NewScalar().SetUniformBytes(q[:])
	return
}

func Generate_pA(w, x *edwards25519.Scalar) (pA *edwards25519.Point) {
	X := new(edwards25519.Point)
	X = X.ScalarMult(x, P)

	pA = new(edwards25519.Point)
	pA = pA.ScalarMult(w, M)
	pA = pA.Add(pA, X)
	return
}

func Generate_pB(w, y *edwards25519.Scalar) (pB *edwards25519.Point) {
	Y := new(edwards25519.Point)
	Y = Y.ScalarMult(y, P)

	pB = new(edwards25519.Point)
	pB = pB.ScalarMult(w, N)
	pB = pB.Add(pB, Y)
	return
}

func AGenerateK(pA, pB *edwards25519.Point, w, x *edwards25519.Scalar) (K *edwards25519.Point) {
	K = new(edwards25519.Point)

	temp := new(edwards25519.Point)
	temp = temp.ScalarMult(w, N)
	K = K.Subtract(pB, temp)
	K = K.ScalarMult(x, K)
	K = K.MultByCofactor(K)
	return
}

func BGenerateK(pA, pB *edwards25519.Point, w, y *edwards25519.Scalar) (K *edwards25519.Point) {
	K = new(edwards25519.Point)

	temp := new(edwards25519.Point)
	temp = temp.ScalarMult(w, M)
	K = K.Subtract(pA, temp)
	K = K.ScalarMult(y, K)
	K = K.MultByCofactor(K)
	return
}

func GenerateSecrets(A, B string, pA, pB, K *edwards25519.Point, w *edwards25519.Scalar) (Ke, cA, cB []byte) {
	TT := new(bytes.Buffer)
	writeVal(TT, []byte(A))
	writeVal(TT, []byte(B))
	writeVal(TT, pA.Bytes())
	writeVal(TT, pB.Bytes())
	writeVal(TT, K.Bytes())
	writeVal(TT, w.Bytes())

	Kpart := sha256.Sum256(TT.Bytes())
	Ke = Kpart[:16]
	Ka := Kpart[16:]

	KcPart, err := hkdf.Key(sha256.New, Ka, nil, "ConfirmationKeys", 32)
	if err != nil {
		panic(err)
	}

	KcA := KcPart[:16]
	KcB := KcPart[16:]

	cA = hmac.New(sha256.New, KcA).Sum(nil)
	cB = hmac.New(sha256.New, KcB).Sum(nil)

	return
}

func RandomScalar() *edwards25519.Scalar {
	b := make([]byte, 64)
	rand.Read(b)
	s, _ := edwards25519.NewScalar().SetUniformBytes(b)
	return s
}

func writeVal(w io.Writer, v []byte) {
	binary.Write(w, binary.LittleEndian, uint64(len(v)))
	w.Write(v)
}
