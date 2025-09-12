package gospake2

import (
	"crypto/rand"
	"errors"
	"slices"
	"testing"
)

type SpakeTest struct {
	name      string
	passwordA string
	passwordB string
	valid     bool
}

var tests = []SpakeTest{
	{
		name:      "valid password",
		passwordA: "password",
		passwordB: "password",
		valid:     true,
	},
	{
		name:      "invalid password",
		passwordA: "passwodsfsdfsdrd",
		passwordB: "passwordssdfsdd2",
		valid:     false,
	},
}

func TestBasic(t *testing.T) {
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			alice, err := NewA([]byte(test.passwordA), "A", "B", rand.Reader, DEFAULT_SUITE)
			if err != nil {
				t.Fatal(err)
			}
			bob, err := NewB([]byte(test.passwordB), "A", "B", rand.Reader, DEFAULT_SUITE)
			if err != nil {
				t.Fatal(err)
			}

			pA, err := alice.Start()
			if err != nil {
				t.Fatal(err)
			}

			pB, err := bob.Start()
			if err != nil {
				t.Fatal(err)
			}

			k, cA, err := alice.Finish(pB)
			if err != nil {
				t.Fatal(err)
			}

			k2, cB, err := bob.Finish(pA)
			if err != nil {
				t.Fatal(err)
			}

			kv := slices.Equal(k, k2)

			var av bool
			err = alice.Verify(cB)
			if err != nil {
				if !errors.Is(err, ErrVerificationFailed) {
					t.Fatal(err)
				}
			} else {
				av = true
			}

			var bv bool
			err = bob.Verify(cA)
			if err != nil {
				if !errors.Is(err, ErrVerificationFailed) {
					t.Fatal(err)
				}
			} else {
				bv = true
			}

			if test.valid {
				if !kv {
					t.Log("Keys do not match")
					t.Fail()
				}

				if !av {
					t.Log("B confirmation messages did not match")
					t.Fail()
				}

				if !bv {
					t.Log("A confirmation messages did not match")
					t.Fail()
				}
			} else {
				if kv {
					t.Log("Keys should not match")
					t.Fail()
				}
				if bv {
					t.Log("B confirmation message should not match")
					t.Fail()
				}

				if av {
					t.Log("A confirmation messages should not match")
					t.Fail()
				}
			}
		})
	}
}
