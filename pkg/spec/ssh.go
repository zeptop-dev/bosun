package spec

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// SSHServer owns the proxy's host key, never the operating system's SSH key.
// Only PublicKey belongs in subscriptions. PrivateKey is an OpenSSH PEM key.
type SSHServer struct {
	PrivateKey string `json:"private_key,omitempty"`
	PublicKey  string `json:"public_key,omitempty"`
}

// SSHClient is the client side of a remote SSH proxy. Keys are inline; no
// filesystem paths or commands are accepted from a panel configuration.
type SSHClient struct {
	PrivateKey string `json:"private_key,omitempty"`
	HostKey    string `json:"host_key"`
}

func (r Remote) validateSSH() error {
	if r.Username == "" {
		return fmt.Errorf("SSH remote requires a username")
	}
	if r.SSH == nil || len(r.SSH.HostKey) > 16384 {
		return fmt.Errorf("SSH remote requires a host public key")
	}
	if _, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(r.SSH.HostKey)); err != nil || len(strings.TrimSpace(string(rest))) != 0 {
		return fmt.Errorf("invalid SSH remote host public key")
	}
	if r.Password == "" && r.SSH.PrivateKey == "" {
		return fmt.Errorf("SSH remote requires a password or private key")
	}
	if len(r.SSH.PrivateKey) > 32768 {
		return fmt.Errorf("SSH client private key is too large")
	}
	if r.SSH.PrivateKey != "" {
		if _, err := ssh.ParsePrivateKey([]byte(r.SSH.PrivateKey)); err != nil {
			return fmt.Errorf("invalid SSH client private key")
		}
	}
	if r.Settings.TLS != nil && r.Settings.TLS.Mode != TLSNone || r.Settings.TransportType() != "tcp" || r.Settings.Multiplex != nil && r.Settings.Multiplex.Enabled {
		return fmt.Errorf("SSH remote does not use TLS, stream transports or sing-mux")
	}
	return nil
}

// EnsureSSHKey creates a stable host identity on save, not on each apply.
func (i *Inbound) EnsureSSHKey() error {
	if i.Protocol != SSH {
		return nil
	}
	if i.SSH == nil {
		i.SSH = &SSHServer{}
	}
	if i.SSH.PrivateKey == "" {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		block, err := ssh.MarshalPrivateKey(key, "bosun proxy")
		if err != nil {
			return err
		}
		i.SSH.PrivateKey = string(pem.EncodeToMemory(block))
	}
	signer, err := ssh.ParsePrivateKey([]byte(i.SSH.PrivateKey))
	if err != nil {
		return fmt.Errorf("SSH host key must be an unencrypted private key")
	}
	i.SSH.PublicKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	return nil
}

func (i Inbound) validateSSH() error {
	if i.SSH == nil || len(i.SSH.PrivateKey) > 32<<10 {
		return fmt.Errorf("SSH host key is required")
	}
	signer, err := ssh.ParsePrivateKey([]byte(i.SSH.PrivateKey))
	if err != nil {
		return fmt.Errorf("invalid SSH host private key")
	}
	pub := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	if i.SSH.PublicKey != pub {
		return fmt.Errorf("SSH host public key does not match the private key")
	}
	if i.TLS != nil && i.TLS.Mode != TLSNone {
		return fmt.Errorf("SSH provides its own encryption; TLS must be off")
	}
	if i.Multiplex != nil && i.Multiplex.Enabled {
		return fmt.Errorf("SSH does not support sing-mux")
	}
	return nil
}

// ProxyUsername preserves the credential UUID while giving SSH / extended
// Mieru a distinct statistics identity for each inbound.
func ProxyUsername(uuid, tag string) string { return InboundUser(uuid, tag) }

func InboundAuthName(i Inbound, u User) string {
	// Naive exposes the login username as metadata.User; retain existing
	// credentials. Its user counters aggregate across Naive listeners.
	if i.Protocol == Naive {
		return u.Name
	}
	if i.Protocol == SSH || i.Protocol == Mieru && i.Core == "singbox-extended" {
		return ProxyUsername(u.UUID, i.Tag)
	}
	return InboundUser(u.Name, i.Tag)
}

func CoreFamily(name string) string {
	if name == "singbox-extended" {
		return "singbox"
	}
	return name
}
