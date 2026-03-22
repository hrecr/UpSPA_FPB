// TODO(UPSPA-SP): Implement this file.
// - Read: docs/apis.md and docs/openapi/sp.yaml (wire contract)
// - Enforce: base64url-no-pad canonicalization + fixed-length checks
// - Never log secrets (uid/suid/cid/cj/k_i/signatures/points)

// Week 2: Fixed critical scalar-clamping bug. See INTERN_NOTES/efe-week2.md.

package crypto

import (
	"errors"
	"fmt"

	"filippo.io/edwards25519"
)

// ErrInvalidPoint is returned when a Ristretto255-encoded point is invalid.
var ErrInvalidPoint = errors.New("invalid_ristretto_point")

// ErrInvalidScalar is returned when bytes do not represent a canonical
// Ristretto255 scalar (i.e. value >= group order l).
var ErrInvalidScalar = errors.New("invalid_ristretto_scalar")

// RistrettoScalarMult computes y = k * blinded where:
//   - k       is a LenScalarKi (32-byte) scalar representing TOPRF share k_i
//   - blinded is a LenRistretto (32-byte) Ristretto255-encoded point
//
// Returns y as a 32-byte Ristretto255-encoded point.
//
// Errors:
//   - ErrWrongLength    if k or blinded have wrong byte lengths
//   - ErrInvalidScalar  if k is not a canonical scalar (value >= group order l)
//   - ErrInvalidPoint   if blinded does not decode as a valid Ristretto255 point
//
// Uses filippo.io/edwards25519 v1.1.0+ which exposes the Ristretto255 group.
// Reference: https://ristretto.group/
//
// NOTE: do NOT log k, blinded, or y — these are secret / sensitive curve values.
func RistrettoScalarMult(k []byte, blinded []byte) (y []byte, err error) {
	if len(k) != LenScalarKi {
		return nil, fmt.Errorf("%w: scalar k must be %d bytes, got %d",
			ErrWrongLength, LenScalarKi, len(k))
	}
	if len(blinded) != LenRistretto {
		return nil, fmt.Errorf("%w: blinded point must be %d bytes, got %d",
			ErrWrongLength, LenRistretto, len(blinded))
	}

	// Decode the scalar using SetCanonicalBytes, NOT SetBytesWithClamping.
	//
	// SetBytesWithClamping is designed for Ed25519/X25519 private keys: it
	// forces specific bit patterns (clears bits 0/1/2/255) before interpreting
	// the bytes as a scalar.  Applied here it would silently compute
	//   clamp(k_i) * blinded   instead of   k_i * blinded
	// — a wrong value with no error signal, breaking the TOPRF protocol.
	//
	// SetCanonicalBytes expects a fully-reduced scalar in [0, l) and returns
	// an error if the value is out of range, which is the correct behaviour:
	// the caller (API handler) must reject such inputs with HTTP 400.
	scalar, err := new(edwards25519.Scalar).SetCanonicalBytes(k)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidScalar, err)
	}

	// Decode the Ristretto255-encoded point.
	point, err := new(edwards25519.Point).SetBytes(blinded)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidPoint, err)
	}

	// y = k * blinded
	result := new(edwards25519.Point).ScalarMult(scalar, point)
	return result.Bytes(), nil
}
