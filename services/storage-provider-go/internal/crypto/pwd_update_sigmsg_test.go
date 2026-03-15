// TODO(UPSPA-SP): Implement this file.
// - Read: docs/apis.md and docs/openapi/sp.yaml (wire contract)
// - Enforce: base64url-no-pad canonicalization + fixed-length checks
// - Never log secrets (uid/suid/cid/cj/k_i/signatures/points)

//1st Week: The underlying cryptology concepts are tried to be skimmed, mostly AI based improved template code written

package crypto_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/your-org/sp/internal/crypto"
)

func TestBuildPwdUpdateSigMsg_TotalLength(t *testing.T) {
	nonce := make([]byte, 24)
	ct := []byte("some-ciphertext-payload")
	tag := make([]byte, 16)
	ki := make([]byte, 32)

	msg := crypto.BuildPwdUpdateSigMsg(nonce, ct, tag, ki, 0, 0)

	want := 24 + len(ct) + 16 + 32 + 8 + 4
	if len(msg) != want {
		t.Errorf("message length: want %d, got %d", want, len(msg))
	}
}

func TestBuildPwdUpdateSigMsg_FieldLayout(t *testing.T) {
	nonce := bytes.Repeat([]byte{0xAA}, 24)
	ct := bytes.Repeat([]byte{0xBB}, 10)
	tag := bytes.Repeat([]byte{0xCC}, 16)
	ki := bytes.Repeat([]byte{0xDD}, 32)
	ts := uint64(0xDEADBEEFCAFEBABE)
	spID := uint32(0x01020304)

	msg := crypto.BuildPwdUpdateSigMsg(nonce, ct, tag, ki, ts, spID)

	offset := 0

	// cidNonce at [0:24]
	if !bytes.Equal(msg[offset:offset+24], nonce) {
		t.Error("cidNonce not at expected position")
	}
	offset += 24

	// cidCt at [24:24+len(ct)]
	if !bytes.Equal(msg[offset:offset+len(ct)], ct) {
		t.Error("cidCt not at expected position")
	}
	offset += len(ct)

	// cidTag at [34:50]
	if !bytes.Equal(msg[offset:offset+16], tag) {
		t.Error("cidTag not at expected position")
	}
	offset += 16

	// kINew at [50:82]
	if !bytes.Equal(msg[offset:offset+32], ki) {
		t.Error("kINew not at expected position")
	}
	offset += 32

	// ts (uint64 LE) at [82:90]
	gotTS := binary.LittleEndian.Uint64(msg[offset : offset+8])
	if gotTS != ts {
		t.Errorf("ts: want 0x%X got 0x%X", ts, gotTS)
	}
	offset += 8

	// spID (uint32 LE) at [90:94]
	gotSpID := binary.LittleEndian.Uint32(msg[offset : offset+4])
	if gotSpID != spID {
		t.Errorf("spID: want 0x%X got 0x%X", spID, gotSpID)
	}
}

func TestBuildPwdUpdateSigMsg_TSLittleEndian(t *testing.T) {
	nonce := make([]byte, 24)
	ct := []byte{}
	tag := make([]byte, 16)
	ki := make([]byte, 32)
	ts := uint64(0x0102030405060708)

	msg := crypto.BuildPwdUpdateSigMsg(nonce, ct, tag, ki, ts, 0)

	// TS starts at offset 24 + 0 + 16 + 32 = 72
	tsOffset := 24 + 0 + 16 + 32
	wantBytes := []byte{0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	if !bytes.Equal(msg[tsOffset:tsOffset+8], wantBytes) {
		t.Errorf("TS little-endian mismatch: want %x got %x", wantBytes, msg[tsOffset:tsOffset+8])
	}
}

func TestBuildPwdUpdateSigMsg_SpIDLittleEndian(t *testing.T) {
	nonce := make([]byte, 24)
	ct := []byte{}
	tag := make([]byte, 16)
	ki := make([]byte, 32)
	spID := uint32(0x01020304)

	msg := crypto.BuildPwdUpdateSigMsg(nonce, ct, tag, ki, 0, spID)

	// spID starts at offset 24 + 0 + 16 + 32 + 8 = 80
	spIDOffset := 24 + 0 + 16 + 32 + 8
	wantBytes := []byte{0x04, 0x03, 0x02, 0x01}
	if !bytes.Equal(msg[spIDOffset:spIDOffset+4], wantBytes) {
		t.Errorf("spID little-endian mismatch: want %x got %x", wantBytes, msg[spIDOffset:spIDOffset+4])
	}
}

func TestBuildPwdUpdateSigMsg_EmptyCt(t *testing.T) {
	msg := crypto.BuildPwdUpdateSigMsg(
		make([]byte, 24),
		[]byte{}, // empty ct
		make([]byte, 16),
		make([]byte, 32),
		0, 0,
	)
	want := 24 + 0 + 16 + 32 + 8 + 4
	if len(msg) != want {
		t.Errorf("empty ct: want len %d, got %d", want, len(msg))
	}
}
