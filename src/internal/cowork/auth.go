package cowork

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"io"
)

// This file implements the two authentication primitives the adversarial review
// required on top of the sealed-box confidentiality:
//
//   - requestMAC (H1): the VM proves it holds the per-exec one-time TOKEN (handed
//     to it via a file descriptor by the hook, never on disk/argv/env) and BINDS
//     its ephemeral public key to that token. Without this, any VM process could
//     write a request with its OWN public key and receive the secret sealed to it.
//   - envelopeBytes (H2): the host signs the WHOLE response envelope
//     (exec_id, status, sealed, error) — not just the sealed blob — so an attacker
//     cannot strip the signature off a real response and inject a forged
//     status/error to abort or mislead the VM.
//
// Both use length-prefixed framing so no field-concatenation collision is possible
// (e.g. ("ab","c") vs ("a","bc") produce distinct digests).

// requestMAC = HMAC-SHA256(token, len‖exec_id ‖ len‖recipient_pub).
func requestMAC(token []byte, execID string, recipientPub []byte) []byte {
	m := hmac.New(sha256.New, token)
	writeLP(m, []byte(execID))
	writeLP(m, recipientPub)
	return m.Sum(nil)
}

// verifyRequestMAC checks a request MAC in constant time. An empty token (no exec
// registered) never verifies.
func verifyRequestMAC(token []byte, execID string, recipientPub, mac []byte) bool {
	if len(token) == 0 || len(mac) == 0 {
		return false
	}
	return hmac.Equal(requestMAC(token, execID, recipientPub), mac)
}

// envelopeBytes is the canonical message the host signs and the VM verifies. It
// covers every authenticity-relevant field of the response.
func envelopeBytes(execID, status string, sealed, errMsg []byte) []byte {
	var b bytes.Buffer
	writeLP(&b, []byte(execID))
	writeLP(&b, []byte(status))
	writeLP(&b, sealed)
	writeLP(&b, errMsg)
	return b.Bytes()
}

func writeLP(w io.Writer, p []byte) {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(p)))
	_, _ = w.Write(l[:])
	_, _ = w.Write(p)
}
