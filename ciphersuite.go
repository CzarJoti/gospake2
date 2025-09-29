package gospake2

import "hash"

// CipherSuite is a ciphersuite for the Spake2 protocol
type CipherSuite[W Point[W, S], S Scalar[S], G Group[W, S]] struct {
	Group        G
	Hash         func() hash.Hash
	PasswordHash func() hash.Hash
	Kdf          func(h func() hash.Hash, ikm []byte, salt []byte, info string, L int) ([]byte, error)
	Mac          func(h func() hash.Hash, key, msg []byte) []byte
}

// Creates a new CipherSuite
func NewCipherSuite[W Point[W, S], S Scalar[S], G Group[W, S]](
	group G,
	hash func() hash.Hash,
	passwordHash func() hash.Hash,
	kdf func(h func() hash.Hash, ikm, salt []byte, info string, L int) ([]byte, error),
	mac func(h func() hash.Hash, key, msg []byte) []byte,
) CipherSuite[W, S, G] {
	return CipherSuite[W, S, G]{
		Group:        group,
		Hash:         hash,
		PasswordHash: passwordHash,
		Kdf:          kdf,
		Mac:          mac,
	}
}
