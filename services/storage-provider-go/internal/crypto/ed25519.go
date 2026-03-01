// TODO(UPSPA-SP): Implement this file.
// - Read: docs/apis.md and docs/openapi/sp.yaml (wire contract)
// - Enforce: base64url-no-pad canonicalization + fixed-length checks
// - Never log secrets (uid/suid/cid/cj/k_i/signatures/points)

//1st Week: The underlying cryptology concepts are tried to be skimmed, mostly AI based improved template code written 

// Implements:
//   - Canonical base64url-no-pad encoding/decoding
//   - Fixed-length byte-array decoding with length enforcement
//   - Ed25519 signature verification
//   - Ristretto255 scalar multiplication (TOPRF evaluation)
//   - Password-update signature message construction

// Security rules enforced here:
//   - NEVER log uid / suid / cid / cj / k_i / signatures / curve points.
//   - All base64 inputs are re-encoded to canonical form before use/storage.
//   - Wrong byte lengths → caller must return 400.

package crypto
 // Imports fundementals
import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"

	"filippo.io/edwards25519"
)

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

// ErrInvalidBase64 is returned when a string is not valid base64url-no-pad.
var ErrInvalidBase64 = errors.New("invalid_base64")

// ErrWrongLength is returned when decoded bytes have an unexpected length.
var ErrWrongLength = errors.New("wrong_byte_length")

// ErrInvalidPoint is returned when a Ristretto point is not on the curve.
var ErrInvalidPoint = errors.New("invalid_ristretto_point")

// Fixed byte-length constants (Shared Contract §2)

const (
	LenEd25519PublicKey = 32
	LenEd25519Signature = 64
	LenCtBlobNonce      = 24
	LenCtBlobTag        = 16
	LenRistretto        = 32
	LenScalarKi         = 32
)

// Base64 helpers

// enc is the canonical encoding: base64url, no padding.
var enc = base64.RawURLEncoding

// CanonicalB64 decodes a base64url-no-pad (or standard base64url with padding)
// string and re-encodes it in canonical form.

// Returns:
//   - canon: canonical base64url-no-pad string (safe to store / compare)
//   - raw:   decoded bytes
//   - err:   ErrInvalidBase64 on any decode failure

// NOTE: Do NOT include raw in log output.
func CanonicalB64(s string) (canon string, raw []byte, err error) {
	raw, err = enc.DecodeString(s)
	if err != nil {
		// Also try with padding stripped, then standard base64url with padding.
		raw, err = base64.URLEncoding.DecodeString(s)
		if err != nil {
			return "", nil, fmt.Errorf("%w: %w", ErrInvalidBase64, err)
		}
	}
	canon = enc.EncodeToString(raw)
	return canon, raw, nil
}

// DecodeFixedB64 decodes a base64url-no-pad string and enforces an exact byte
// length n. Returns canonical form alongside raw bytes.

// Returns ErrInvalidBase64 on bad encoding, ErrWrongLength on length mismatch.

// NOTE: Do NOT include raw or canon in log output for secret fields.
func DecodeFixedB64(s string, n int) (raw []byte, canon string, err error) {
	canon, raw, err = CanonicalB64(s)
	if err != nil {
		return nil, "", err
	}
	if len(raw) != n {
		return nil, "", fmt.Errorf("%w: want %d bytes, got %d", ErrWrongLength, n, len(raw))
	}
	return raw, canon, nil
}

// Ed25519

// VerifyEd25519 returns true iff sig is a valid Ed25519 signature over msg
// produced by the key sigPk.

// sigPk must be 32 bytes; sig must be 64 bytes. The function panics on wrong
// lengths — callers must use DecodeFixedB64 with the correct constants first.
func VerifyEd25519(sigPk []byte, msg []byte, sig []byte) bool {
	if len(sigPk) != LenEd25519PublicKey {
		panic(fmt.Sprintf("crypto.VerifyEd25519: sigPk must be %d bytes, got %d", LenEd25519PublicKey, len(sigPk)))
	}
	if len(sig) != LenEd25519Signature {
		panic(fmt.Sprintf("crypto.VerifyEd25519: sig must be %d bytes, got %d", LenEd25519Signature, len(sig)))
	}
	return ed25519.Verify(ed25519.PublicKey(sigPk), msg, sig)
}

// Ristretto255 scalar multiplication (TOPRF)

// RistrettoScalarMult computes y = k * blinded where:
//   - k      is a 32-byte scalar (TOPRF share k_i, little-endian)
//   - blinded is a 32-byte Ristretto255-encoded point (client-blinded input)

// Returns y as a 32-byte Ristretto255-encoded point, or an error if either
// input is invalid.

// Uses filippo.io/edwards25519 which exposes the Ristretto255 group.
// Import path: filippo.io/edwards25519 v1.1.0+

// NOTE: Do NOT log k, blinded, or y — these are secret / sensitive curve values.
func RistrettoScalarMult(k []byte, blinded []byte) (y []byte, err error) {
	if len(k) != LenScalarKi {
		return nil, fmt.Errorf("%w: scalar k must be %d bytes, got %d", ErrWrongLength, LenScalarKi, len(k))
	}
	if len(blinded) != LenRistretto {
		return nil, fmt.Errorf("%w: blinded point must be %d bytes, got %d", ErrWrongLength, LenRistretto, len(blinded))
	}

	// Decode the blinded point.
	point, err := new(edwards25519.Point).SetBytes(blinded)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidPoint, err)
	}

	// Decode the scalar (clamp for Ristretto255 scalar multiplication).
	scalar, err := new(edwards25519.Scalar).SetBytesWithClamping(k)
	if err != nil {
		return nil, fmt.Errorf("invalid scalar: %w", err)
	}

	// y = k * blinded
	result := new(edwards25519.Point).ScalarMult(scalar, point)
	return result.Bytes(), nil
}

// Password-update signature message construction

// BuildPwdUpdateSigMsg constructs the exact byte sequence that the client
// signs during a password-update request.

// Layout (from docs/protocol-phases.md):

//	[cidNonce (24)] || [cidCt (variable)] || [cidTag (16)] || [kINew (32)] || [tsU64LE (8)] || [spIDU32LE (4)]

// All inputs are raw bytes (already decoded from base64).
// tsU64LE and spIDU32LE are passed as uint64/uint32; encoded little-endian here.

// NOTE: do NOT log the return value — it contains key material.
func BuildPwdUpdateSigMsg(
	cidNonce []byte, // 24 bytes
	cidCt []byte, // variable
	cidTag []byte, // 16 bytes
	kINew []byte, // 32 bytes
	tsU64LE uint64,
	spIDU32LE uint32,
) []byte {
	tsBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(tsBytes, tsU64LE)

	spIDBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(spIDBytes, spIDU32LE)

	// Pre-allocate the full message.
	totalLen := len(cidNonce) + len(cidCt) + len(cidTag) + len(kINew) + 8 + 4
	msg := make([]byte, 0, totalLen)

	msg = append(msg, cidNonce...)
	msg = append(msg, cidCt...)
	msg = append(msg, cidTag...)
	msg = append(msg, kINew...)
	msg = append(msg, tsBytes...)
	msg = append(msg, spIDBytes...)

	return msg
}
