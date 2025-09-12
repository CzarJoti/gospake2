#gospake2

An implementation of the Spake2 password-authenticated key exchange protocol as described in [RFC 9382](https://www.rfc-editor.org/rfc/rfc9382) in Go. 

##Overview

Spake2 is a secure password-authenticated key exchange protocol that allows two parties that share a weak password to derive a strong shared key without disclosing the password. 

##Implementation
gospake2 provides a default ciphersuite for use with the Spake2 protocol as the variable DEFAULT_SUITE
It uses the edwards25519 curve as its group, SHA256 as its hash function, SHA512 to hash the provided password, HKDF for its key derivation function, and HMAC for its Message Authentication Code algorithm

###Note:
SHA512 as the password hash function provided by the default ciphersuite is NOT MEMORY-HARD and is NOT the recomended hash function for any secure application. It is included in DEFAULT_SUITE due to its speed for low-security applications

##Usage

First, both sides are initialized with the same password and messages containing pA and pB are created

```go
package main

import spake2 "github.com/ValiantChip/gospake2"

a := spake2.NewA(password, "A", "B", rand.Reader, spake2.DEFAULT_SUITE)
amsg, err := a.Start()
//handle err

b := spake2.NewB(password, "A", "B", rand.Reader, spake2.DEFAULT_SUITE)
bmsg, err := b.Start()
//handle err
```

The messages are then exchanged between a and b and the shared key and confirmation messages are created

```go
K_a, aConf, err := a.Finish(bmsg)
//handle err

K_b, bConf, err := b.Finish(amsg)
//handle err
```

The confirmation messages are then shared between a and b and are verified to determine if the protocol was successful

```go
err := a.Verify(bConf)
//handle err

err := b.Verify(aConf)
//hand err
```

The protocol is now complete and a and b have the shared key K

## Installation

Use go get to install this package

```bash
go get github.com/ValiantChip/gospake2
```



