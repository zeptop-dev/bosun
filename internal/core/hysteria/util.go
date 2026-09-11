package hysteria

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
)

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

func randomSecret() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
