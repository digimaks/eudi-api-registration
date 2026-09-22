// Package apikeys mints verification API keys ("vk_<prefix>_<secret>" +
// argon2id PHC hash). This is a byte-for-byte mirror of the session
// service's own key-minting logic (kept in a copy because it lives in
// another module's un-importable internal/ package); keep the two in
// lockstep — a format change (argon2id params, key scheme prefix, encoding)
// in one must be mirrored in the other, or a key minted here becomes
// unverifiable there.
//
// This package only ever MINTS keys (this service never verifies a presented
// X-API-Key — the session service verifies presented keys, not this service)
// — so unlike the full session-service copy, there is no Parse/Verify half
// here, only Mint. The centralized crypto allow-lists (go-eudi-crypto) cover
// JOSE/COSE signing+encryption algorithms; argon2id is a password-style KDF
// for hash-at-rest, not a signing algorithm, so golang.org/x/crypto/argon2
// is used directly here, exactly as the session service's own copy does.
package apikeys

import (
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters — pinned identical to the session service's own copy
// (OWASP Password Storage Cheat Sheet's second recommended configuration:
// m=19 MiB, t=2, p=1, 128-bit salt, 256-bit tag). Any drift here from that
// copy would mean a key minted by one service could never be verified by the
// other.
const (
	argonMemoryKiB = 19456
	argonTime      = 2
	argonThreads   = 1
	argonVersion   = argon2.Version

	saltLen      = 16
	tagLen       = 32
	prefixRawLen = 5
	secretRawLen = 24

	keyScheme = "vk"
)

// crockford32 is Crockford's Base32 alphabet (excludes I, L, O, U to avoid
// visual ambiguity with 1/0) — used only for the public, non-secret
// key-lookup prefix, never for the secret itself.
var crockford32 = base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").WithPadding(base32.NoPadding)

// Mint generates a fresh key: the caller-facing display key (returned to the
// client exactly once), the public row prefix, and the argon2id PHC hash —
// the ONLY part that may be persisted. r is the randomness source
// (crypto/rand.Reader in production).
func Mint(r io.Reader) (displayKey, prefix, phcHash string, err error) {
	prefixRaw := make([]byte, prefixRawLen)
	if _, err := io.ReadFull(r, prefixRaw); err != nil {
		return "", "", "", fmt.Errorf("apikeys: mint prefix: %w", err)
	}
	prefix = crockford32.EncodeToString(prefixRaw)

	secretRaw := make([]byte, secretRawLen)
	if _, err := io.ReadFull(r, secretRaw); err != nil {
		return "", "", "", fmt.Errorf("apikeys: mint secret: %w", err)
	}
	secret := base64.RawURLEncoding.EncodeToString(secretRaw)

	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(r, salt); err != nil {
		return "", "", "", fmt.Errorf("apikeys: mint salt: %w", err)
	}
	tag := argon2.IDKey([]byte(secret), salt, argonTime, argonMemoryKiB, argonThreads, tagLen)

	phcHash = fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argonVersion, argonMemoryKiB, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(tag))

	return keyScheme + "_" + prefix + "_" + secret, prefix, phcHash, nil
}
