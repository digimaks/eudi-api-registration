package apikeys

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/go-quicktest/qt"
	"golang.org/x/crypto/argon2"
)

// TestMintShapeAndVerify pins Mint's key shape ("vk_<prefix>_<secret>") and
// PHC hash format when read from crypto/rand, and proves the hash verifies
// against the exact secret it was minted for by independently recomputing
// the argon2id tag (never calling back into this package's own internals).
//
// The literal "m=19456,t=2,p=1" pin is deliberate: this package is a recorded
// duplicate of the session service's own copy of the same Mint half (see the
// package doc comment) — a silent parameter drift between the two copies
// would otherwise only ever be caught by comparing them by eye. Pinning the
// exact PHC parameter string here makes THIS copy's params fail loudly the
// moment they stop matching what was recorded.
func TestMintShapeAndVerify(t *testing.T) {
	displayKey, prefix, phcHash, err := Mint(rand.Reader)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(prefix != ""))

	qt.Assert(t, qt.IsTrue(strings.HasPrefix(displayKey, "vk_"+prefix+"_")))
	secret := strings.TrimPrefix(displayKey, "vk_"+prefix+"_")
	qt.Assert(t, qt.IsTrue(secret != ""))

	// Length pins: the session service's Parse hard-requires exactly these
	// encoded lengths (prefixLen 8, secretLen 32) — a drifted
	// prefixRawLen/secretRawLen in this lockstep copy must fail HERE, not at
	// first real use against the session service.
	qt.Assert(t, qt.Equals(len(prefix), 8))
	qt.Assert(t, qt.Equals(len(secret), 32))

	qt.Assert(t, qt.IsTrue(strings.HasPrefix(phcHash, "$argon2id$v=19$m=19456,t=2,p=1$")))

	parts := strings.Split(phcHash, "$")
	qt.Assert(t, qt.Equals(len(parts), 6))
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	qt.Assert(t, qt.IsNil(err))
	tag, err := base64.RawStdEncoding.DecodeString(parts[5])
	qt.Assert(t, qt.IsNil(err))

	gotTag := argon2.IDKey([]byte(secret), salt, 2, 19456, 1, 32)
	qt.Assert(t, qt.IsTrue(subtle.ConstantTimeCompare(gotTag, tag) == 1))
}

// TestMintDistinctPerCall guards against a degenerate reader/implementation
// that would mint the same key twice in a row — crypto/rand.Reader gives
// each call fresh bytes, so two consecutive mints must differ in both the
// display key and the resulting hash.
func TestMintDistinctPerCall(t *testing.T) {
	key1, _, phc1, err := Mint(rand.Reader)
	qt.Assert(t, qt.IsNil(err))
	key2, _, phc2, err := Mint(rand.Reader)
	qt.Assert(t, qt.IsNil(err))

	qt.Check(t, qt.Not(qt.Equals(key1, key2)))
	qt.Check(t, qt.Not(qt.Equals(phc1, phc2)))
}
