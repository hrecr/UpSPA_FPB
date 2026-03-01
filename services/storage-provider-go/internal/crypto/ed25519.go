//1st Week: The underlying cryptology concepts are tried to be skimmed, mostly AI based improved template code written

package crypto

import (
	"crypto/ed25519"
	"fmt"
)

// VerifyEd25519 returns true iff sig is a valid Ed25519 signature over msg
// produced by the key sigPk.
//
// sigPk must be LenEd25519PublicKey (32) bytes.
// sig   must be LenEd25519Signature (64) bytes.
//
// The function panics on wrong lengths — callers MUST use DecodeFixedB64 with
// the correct Len* constants before calling this function.
//
// References:
//   - https://pkg.go.dev/crypto/ed25519
//   - https://datatracker.ietf.org/doc/html/rfc8032
//
// NOTE: do NOT log sigPk, msg, or sig.
func VerifyEd25519(sigPk []byte, msg []byte, sig []byte) bool {
	if len(sigPk) != LenEd25519PublicKey {
		panic(fmt.Sprintf(
			"crypto.VerifyEd25519: sigPk must be %d bytes, got %d",
			LenEd25519PublicKey, len(sigPk),
		))
	}
	if len(sig) != LenEd25519Signature {
		panic(fmt.Sprintf(
			"crypto.VerifyEd25519: sig must be %d bytes, got %d",
			LenEd25519Signature, len(sig),
		))
	}
	return ed25519.Verify(ed25519.PublicKey(sigPk), msg, sig)
}
