// Package broker delivers vault-resolved secret values from the host (where the
// vault CLIs live) to the Cowork VM (where commands run) over an authenticated,
// encrypted channel — so the value is used only in the VM's memory and never
// touches its disk, shell history or the agent transcript.
//
// The host runs the resolving authority (Server); the VM runs the value consumer
// (Client). The transport works in two directions, negotiated via a bootstrap
// file on the shared `outputs` spool:
//
//   - Plan A: the host binds a TLS listener on the vmnet bridge; the VM dials in.
//   - Plan B: the VM binds a TLS listener; the host dials in (rendezvous via spool).
//
// In BOTH plans the host plays the protocol "server" role (it owns the secrets)
// and the VM plays the protocol "client" role — independent of who dialed. The
// secret value always travels over the TLS socket, never through the spool.
package broker

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// newServerTLS generates an ephemeral self-signed certificate for a TLS listener
// and returns the tls.Config plus the SHA-256 fingerprint (hex) of the
// certificate, which the dialing peer pins. The key never leaves memory.
func newServerTLS() (*tls.Config, string, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject:      pkix.Name{CommonName: "secrets-guard-broker"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, "", err
	}
	fp := sha256.Sum256(der)
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	return cfg, hex.EncodeToString(fp[:]), nil
}

// pinnedClientTLS returns a tls.Config that does not use the system CA chain but
// instead requires the peer certificate to match the pinned SHA-256 fingerprint.
// Pinning is MANDATORY: an empty fingerprint is rejected (fail-closed), so a
// tampered bootstrap/rendezvous with `cert_fp:""` cannot silently downgrade the
// channel to accept any certificate. The application-layer HMAC handshake
// authenticates token knowledge; the pin additionally blocks a TLS MITM.
func pinnedClientTLS(fpHex string) *tls.Config {
	want := strings.ToLower(strings.TrimSpace(fpHex))
	return &tls.Config{
		// We verify the peer by pinned fingerprint below, not via a CA.
		InsecureSkipVerify: true, //nolint:gosec // pinned in VerifyPeerCertificate
		MinVersion:         tls.VersionTLS12,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if want == "" {
				return fmt.Errorf("no certificate pin provided (refusing unpinned connection)")
			}
			for _, raw := range rawCerts {
				fp := sha256.Sum256(raw)
				if hex.EncodeToString(fp[:]) == want {
					return nil
				}
			}
			return fmt.Errorf("peer certificate fingerprint mismatch (possible MITM)")
		},
	}
}
