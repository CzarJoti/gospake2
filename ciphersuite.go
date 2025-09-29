package gospake2

import "hash"

// CipherSuite is a ciphersuite for the Spake2 protocol
type CipherSuite[S Scalar[S], W Point[W, S], G Group[W, S]] struct {
	Group        G
	Hash         func() hash.Hash
	PasswordHash func() hash.Hash
	Kdf          func(func() hash.Hash, []byte, []byte, string, int) ([]byte, error)
	Mac          func(func() hash.Hash, []byte) hash.Hash
}

// Creates a new CipherSuite
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
