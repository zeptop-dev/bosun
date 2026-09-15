package backup

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
)

// Archives can be passphrase-protected: the tar.gz is sealed with
// AES-256-GCM under an argon2id key. Layout: magic, 16-byte salt, 12-byte
// nonce, ciphertext. The archive carries every node secret (admin hash,
// TOTP, API-token hashes, user credentials, WARP key, Cloudflare and
// Telegram tokens), so the panel asks for a passphrase by default.
const magic = "BOSUNBK1"

func deriveKey(passphrase string, salt []byte) []byte {
	return argon2.IDKey([]byte(passphrase), salt, 3, 64*1024, 2, 32)
}

// Seal encrypts plain with the passphrase into w.
func Seal(w io.Writer, plain []byte, passphrase string) error {
	if passphrase == "" {
		return errors.New("backup: passphrase is empty")
	}
	salt := make([]byte, 16)
	nonce := make([]byte, 12)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	block, err := aes.NewCipher(deriveKey(passphrase, salt))
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	for _, part := range [][]byte{[]byte(magic), salt, nonce, gcm.Seal(nil, nonce, plain, []byte(magic))} {
		if _, err := w.Write(part); err != nil {
			return err
		}
	}
	return nil
}

// Open returns a reader over the archive: encrypted input is decrypted
// with the passphrase (an error names a missing or wrong one), plain
// tar.gz passes through unchanged.
func Open(r io.Reader, passphrase string) (io.Reader, error) {
	br := bufio.NewReader(r)
	head, err := br.Peek(len(magic))
	if err != nil || string(head) != magic {
		return br, nil
	}
	if passphrase == "" {
		return nil, errors.New("backup: this archive is encrypted; a passphrase is required")
	}
	all, err := io.ReadAll(io.LimitReader(br, 256<<20))
	if err != nil {
		return nil, err
	}
	if len(all) < len(magic)+16+12+16 {
		return nil, errors.New("backup: encrypted archive is truncated")
	}
	salt := all[len(magic) : len(magic)+16]
	nonce := all[len(magic)+16 : len(magic)+28]
	block, err := aes.NewCipher(deriveKey(passphrase, salt))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, all[len(magic)+28:], []byte(magic))
	if err != nil {
		return nil, errors.New("backup: wrong passphrase")
	}
	return bytes.NewReader(plain), nil
}
