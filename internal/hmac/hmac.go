package hmac

import (
	"crypto/hmac"
	"hash"
)

func MAC(h func() hash.Hash, key, msg []byte) []byte {
	mac := hmac.New(h, key)
	mac.Write(msg)
	return mac.Sum(nil)
}
