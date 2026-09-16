//go:build !linux

package runas

import "syscall"

// Credential: only Linux drops privileges for cores; elsewhere (dev
// machines) the child inherits bosun's identity.
func Credential() *syscall.SysProcAttr { return nil }
