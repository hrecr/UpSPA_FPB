// TODO(UPSPA-SP): Implement this file.
// - Read: docs/apis.md and docs/openapi/sp.yaml (wire contract)
// - Enforce: base64url-no-pad canonicalization + fixed-length checks
// - Never log secrets (uid/suid/cid/cj/k_i/signatures/points)

//1st Week: The underlying cryptology concepts are tried to be skimmed, mostly AI based improved template code written

package crypto_test

import (
	"crypto/rand"
	"errors"
	"testing"

	"filippo.io/edwards25519"
	"github.com/your-org/sp/internal/crypto"
)

// validRistrettoPoint returns a known-valid Ristretto255 point (the base point).
func validRistrettoPoint() []byte {
	// Use the Edwards25519 base point, which is also a valid Ristretto255 point.
	return edwards25519.NewGeneratorPoint().Bytes()
}

func TestRistrettoScalarMult_ValidInputs(t *testing.T) {
	k := make([]byte, 32)
	rand.Read(k)

	point := validRistrettoPoint()
	y, err := crypto.RistrettoScalarMult(k, point)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(y) != 32 {
		t.Errorf("expected 32-byte output, got %d", len(y))
	}
}

func TestRistrettoScalarMult_Deterministic(t *testing.T) {
	k := make([]byte, 32)
	rand.Read(k)
	point := validRistrettoPoint()

	y1, err := crypto.RistrettoScalarMult(k, point)
	if err != nil {
		t.Fatal(err)
	}
	y2, err := crypto.RistrettoScalarMult(k, point)
	if err != nil {
		t.Fatal(err)
	}
	if string(y1) != string(y2) {
		t.Error("RistrettoScalarMult is not deterministic")
	}
}

func TestRistrettoScalarMult_DifferentKeys_DifferentOutputs(t *testing.T) {
	k1 := make([]byte, 32)
	k2 := make([]byte, 32)
	rand.Read(k1)
	rand.Read(k2)
	point := validRistrettoPoint()

	y1, _ := crypto.RistrettoScalarMult(k1, point)
	y2, _ := crypto.RistrettoScalarMult(k2, point)

	if string(y1) == string(y2) {
		t.Error("different scalars should (almost certainly) produce different outputs")
	}
}

func TestRistrettoScalarMult_InvalidPoint(t *testing.T) {
	k := make([]byte, 32)
	rand.Read(k)

	badPoint := make([]byte, 32) // all-zero is not a valid Ristretto255 point
	_, err := crypto.RistrettoScalarMult(k, badPoint)
	if err == nil {
		t.Fatal("expected error for invalid Ristretto point")
	}
	if !errors.Is(err, crypto.ErrInvalidPoint) {
		t.Errorf("want ErrInvalidPoint, got %v", err)
	}
}

func TestRistrettoScalarMult_WrongScalarLength(t *testing.T) {
	_, err := crypto.RistrettoScalarMult(make([]byte, 16), validRistrettoPoint())
	if !errors.Is(err, crypto.ErrWrongLength) {
		t.Errorf("want ErrWrongLength for short scalar, got %v", err)
	}
}

func TestRistrettoScalarMult_WrongPointLength(t *testing.T) {
	k := make([]byte, 32)
	rand.Read(k)
	_, err := crypto.RistrettoScalarMult(k, make([]byte, 16))
	if !errors.Is(err, crypto.ErrWrongLength) {
		t.Errorf("want ErrWrongLength for short point, got %v", err)
	}
}
