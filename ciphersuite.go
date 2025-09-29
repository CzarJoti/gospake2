package gospake2

import "hash"

// CipherSuite is a ciphersuite for the Spake2 protocol
type CipherSuite[W Point[W, S], S Scalar[S], G Group[W, S]] struct {
	Group        G
	Hash         func() hash.Hash
	PasswordHash func() hash.Hash
	Kdf          func(func() hash.Hash, []byte, []byte, string, int) ([]byte, error)
	Mac          func(func() hash.Hash, []byte) hash.Hash
}

// Creates a new CipherSuite
func NewCipherSuite[W Point[W, S], S Scalar[S], G Group[W, S]](
	group G,
	hash func() hash.Hash,
	passwordHash func() hash.Hash,
	kdf func(func() hash.Hash, []byte, []byte, string, int) ([]byte, error),
	mac func(func() hash.Hash, []byte) hash.Hash,
) CipherSuite[W, S, G] {
	return CipherSuite[W, S, G]{
		Group:        group,
		Hash:         hash,
		PasswordHash: passwordHash,
		Kdf:          kdf,
		Mac:          mac,
	}
}
