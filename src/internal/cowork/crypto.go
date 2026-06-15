// Package cowork implements the secure secret channel for Claude Cowork, where
// the agent's commands run in an isolated Linux VM that has NO vault CLI and NO
// network path to the host — the ONLY host↔VM channel is a shared on-disk
// directory (the `outputs` mount), which is persisted and surfaced to the model.
//
// The design makes that disk channel safe with asymmetric (sealed-box) crypto:
//
//   - The VM generates an EPHEMERAL X25519 keypair entirely in memory. The
//     PRIVATE key NEVER touches disk, the command line, or the model.
//   - The VM writes a request to the spool carrying only its PUBLIC key, the
//     references, and an exec id — none of which are secret.
//   - The host (which has the vault CLI) resolves the references and SEALS the
//     values to the VM's public key (ECIES: ephemeral-static X25519 → HKDF →
//     AES-256-GCM), then SIGNS the sealed blob (Ed25519) so the VM can reject a
//     forged response.
//   - The VM opens the sealed blob with its in-memory private key, uses the value
//     only in the child process's memory, and discards the key.
//
// Consequences that satisfy the two hard requirements:
//   - "Token not persisted": nothing secret is ever placed on the command line or
//     the spool — only public keys, references and ciphertext. The decryption
//     material (the VM private key) is never transmitted.
//   - "Captured-in-window is useless": an attacker who captures BOTH the request
//     (public key) AND the response (ciphertext) during the live window still
//     cannot decrypt — the private key existed only in the VM process's RAM and
//     is gone. There is no symmetric key to capture.
package cowork

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
)

// sealedOverhead = ephemeral pubkey (32) + GCM nonce (12) + GCM tag (16).
const (
	x25519PubLen = 32
	gcmNonceLen  = 12
)

// seal encrypts plaintext to the recipient's X25519 public key (anonymous
// sender / sealed box). aad binds the ciphertext to a context (the exec id) so a
// blob cannot be replayed into a different exchange. Returns ephPub||nonce||ct.
func seal(recipientPub *ecdh.PublicKey, plaintext, aad []byte) ([]byte, error) {
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := eph.ECDH(recipientPub)
	if err != nil {
		return nil, err
	}
	key, err := deriveKey(shared, eph.PublicKey().Bytes(), recipientPub.Bytes())
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcmNonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, plaintext, aad)
	out := make([]byte, 0, x25519PubLen+gcmNonceLen+len(ct))
	out = append(out, eph.PublicKey().Bytes()...)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// open decrypts a sealed blob with the recipient's private key. aad must match
// what was used to seal.
func open(recipientPriv *ecdh.PrivateKey, blob, aad []byte) ([]byte, error) {
	if len(blob) < x25519PubLen+gcmNonceLen {
		return nil, fmt.Errorf("sealed blob too short")
	}
	ephPubBytes := blob[:x25519PubLen]
	nonce := blob[x25519PubLen : x25519PubLen+gcmNonceLen]
	ct := blob[x25519PubLen+gcmNonceLen:]
	ephPub, err := ecdh.X25519().NewPublicKey(ephPubBytes)
	if err != nil {
		return nil, err
	}
	shared, err := recipientPriv.ECDH(ephPub)
	if err != nil {
		return nil, err
	}
	key, err := deriveKey(shared, ephPubBytes, recipientPriv.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ct, aad)
}

// deriveKey turns the ECDH shared secret into a 256-bit AES key, binding both
// public keys so the key is unique to this (ephemeral, recipient) pair.
func deriveKey(shared, ephPub, recipientPub []byte) ([]byte, error) {
	info := make([]byte, 0, len(ephPub)+len(recipientPub))
	info = append(info, ephPub...)
	info = append(info, recipientPub...)
	return hkdf.Key(sha256.New, shared, nil, string(append([]byte("secrets-guard/cowork/v1|"), info...)), 32)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// --- ephemeral recipient keypair (VM side, memory only) ---

// genRecipient returns a fresh X25519 keypair for one exchange. The private key
// is held only in memory by the caller and never serialized.
func genRecipient() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

// --- host response authenticity (Ed25519) ---

// hostSigner holds the host's Ed25519 signing key. The public half is published
// to the VM non-secretly (in the bootstrap); the private half stays on the host.
type hostSigner struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func newHostSigner() (*hostSigner, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &hostSigner{priv: priv, pub: pub}, nil
}

func (h *hostSigner) sign(msg []byte) []byte { return ed25519.Sign(h.priv, msg) }

// verifyHost checks a host signature over msg with the published host public key.
func verifyHost(hostPub ed25519.PublicKey, msg, sig []byte) bool {
	if len(hostPub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(hostPub, msg, sig)
}
