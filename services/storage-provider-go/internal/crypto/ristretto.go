// TODO(UPSPA-SP): Implement this file.
// - Read: docs/apis.md and docs/openapi/sp.yaml (wire contract)
// - Enforce: base64url-no-pad canonicalization + fixed-length checks
// - Never log secrets (uid/suid/cid/cj/k_i/signatures/points)

//1st Week: The underlying cryptology concepts are tried to be skimmed, mostly AI based improved template code written

package crypto

import (
	"errors"
	"fmt"

	"filippo.io/edwards25519"
)

// ErrInvalidPoint is returned when a Ristretto255-encoded point is invalid.
var ErrInvalidPoint = errors.New("invalid_ristretto_point")

// RistrettoScalarMult computes y = k * blinded where:
//   - k       is a LenScalarKi (32-byte) scalar representing TOPRF share k_i
//   - blinded is a LenRistretto (32-byte) Ristretto255-encoded point
//
// Returns y as a 32-byte Ristretto255-encoded point.
//
// Errors:
//   - ErrWrongLength  if k or blinded have wrong byte lengths
//   - ErrInvalidPoint if blinded does not decode as a valid Ristretto255 point
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

	// Decode the Ristretto255-encoded point.
	point, err := new(edwards25519.Point).SetBytes(blinded)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidPoint, err)
	}

	// Clamp and decode the scalar.
	scalar, err := new(edwards25519.Scalar).SetBytesWithClamping(k)
	if err != nil {
		return nil, fmt.Errorf("invalid scalar: %w", err)
	}

	// y = k * blinded
	result := new(edwards25519.Point).ScalarMult(scalar, point)
	return result.Bytes(), nil
}
