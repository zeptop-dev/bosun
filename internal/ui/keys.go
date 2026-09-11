package ui

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
)

// realityKeys returns an x25519 pair in the encoding Xray and sing-box use
// (base64 without padding, URL alphabet).
func realityKeys() (priv, pub string, err error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.RawURLEncoding.EncodeToString(k.Bytes()), base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}
