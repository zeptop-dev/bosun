// Package wg holds the WireGuard key helpers shared by the node and the
// panel. Per-user client keys are derived from the inbound's private key
// and the user's UUID, so neither side stores anything extra and both
// produce the same client config.
package wg

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/curve25519"
)

// DefaultAddress is the server side of the tunnel network.
const DefaultAddress = "10.66.0.1/16"

// DefaultMTU suits most paths (WireGuard's own default is 1420).
const DefaultMTU = 1420

func clamp(k []byte) {
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
}

// Keypair returns a fresh private/public pair, base64 like wg(8).
func Keypair() (priv, pub string, err error) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return "", "", err
	}
	clamp(k)
	p, err := curve25519.X25519(k, curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(k), base64.StdEncoding.EncodeToString(p), nil
}

// PublicKey derives the public key of a base64 private key.
func PublicKey(priv string) (string, error) {
	k, err := base64.StdEncoding.DecodeString(priv)
	if err != nil || len(k) != 32 {
		return "", errors.New("wireguard: private key must be 32 bytes base64")
	}
	p, err := curve25519.X25519(k, curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(p), nil
}

// DerivePeer returns the client key pair for one user of one inbound:
// HMAC-SHA256(serverPrivateKey, uuid), clamped. Rotating the server key
// re-keys every client.
func DerivePeer(serverPriv, uuid string) (priv, pub string, err error) {
	return derivePeer(serverPriv, "bosun-wireguard-peer:"+uuid)
}

// DeriveDevicePeer derives an independent identity for a registered device.
// Including the account identity preserves account-wide credential rotation.
// The separate domain prevents a device identity colliding with a legacy one.
func DeriveDevicePeer(serverPriv, userUUID, deviceUUID string) (priv, pub string, err error) {
	if userUUID == "" || deviceUUID == "" || strings.ContainsRune(userUUID, 0) || strings.ContainsRune(deviceUUID, 0) {
		return "", "", errors.New("wireguard: invalid device identity")
	}
	return derivePeer(serverPriv, "bosun-wireguard-device:"+userUUID+"\x00"+deviceUUID)
}

func derivePeer(serverPriv, identity string) (priv, pub string, err error) {
	sk, err := base64.StdEncoding.DecodeString(serverPriv)
	if err != nil || len(sk) != 32 {
		return "", "", errors.New("wireguard: server private key must be 32 bytes base64")
	}
	mac := hmac.New(sha256.New, sk)
	mac.Write([]byte(identity))
	k := mac.Sum(nil)
	clamp(k)
	p, err := curve25519.X25519(k, curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(k), base64.StdEncoding.EncodeToString(p), nil
}

// DeviceAddress is a distinct /32 for a monotonically allocated device id.
// IDs must not be reused after revocation. Exhaustion fails instead of wrapping.
func DeviceAddress(deviceID int64) (string, error) {
	if deviceID < 1 || deviceID > 65534 {
		return "", errors.New("wireguard: device address pool exhausted or invalid id")
	}
	return fmt.Sprintf("10.67.%d.%d/32", deviceID>>8, deviceID&255), nil
}

// ClientAddress is the /32 a user gets inside the tunnel network: derived
// from the user id so it is stable and unique (up to ~65k users).
func ClientAddress(userID int64) string {
	n := userID + 1 // .0.1 is the server
	o3 := (n / 254) % 256
	o4 := n%254 + 1
	return fmt.Sprintf("10.66.%d.%d/32", o3, o4)
}
