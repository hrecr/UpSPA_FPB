// TODO(UPSPA-SP): Implement this file.
// - Read: docs/apis.md and docs/openapi/sp.yaml (wire contract)
// - Enforce: base64url-no-pad canonicalization + fixed-length checks
// - Never log secrets (uid/suid/cid/cj/k_i/signatures/points)

//1st Week: The underlying cryptology concepts are tried to be skimmed, mostly AI based improved template code written

package crypto

import "encoding/binary"

// BuildPwdUpdateSigMsg constructs the exact byte sequence that the client
// signs during a password-update request.
//
// Layout (from docs/protocol-phases.md):
//
//	[cidNonce (24 bytes)]
//	[cidCt    (variable)]
//	[cidTag   (16 bytes)]
//	[kINew    (32 bytes)]
//	[ts       ( 8 bytes, uint64 little-endian)]
//	[spID     ( 4 bytes, uint32 little-endian)]
//
// All slice inputs are raw bytes (already decoded from base64).
// tsU64LE and spIDU32LE are encoded to little-endian here.
//
// NOTE: do NOT log the return value — it contains key material (kINew, cid).
func BuildPwdUpdateSigMsg(
	cidNonce []byte, // 24 bytes
	cidCt []byte, // variable length
	cidTag []byte, // 16 bytes
	kINew []byte, // 32 bytes
	tsU64LE uint64,
	spIDU32LE uint32,
) []byte {
	tsBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(tsBytes, tsU64LE)

	spIDBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(spIDBytes, spIDU32LE)

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
