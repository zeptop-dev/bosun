//go:build linux

package runas

import "syscall"

const (
	capNetBindService = 10
	capNetAdmin       = 12
)

// Credential is the SysProcAttr that runs a child as the core account with
// only CAP_NET_BIND_SERVICE (ports below 1024); nil when none is set.
// Supplementary groups are cleared: bosun's own groups (root, adm, disk on
// some systems) must not survive into a core.
func Credential() *syscall.SysProcAttr { return credential(false) }

// CredentialMarking is Credential plus CAP_NET_ADMIN while a speed limit
// exists, for the two cores that mark sockets (SO_MARK). No other core
// gets it: a capability handed to every child would make the egress guard
// removable by any of them.
func CredentialMarking() *syscall.SysProcAttr { return credential(NetAdmin()) }

func credential(netAdmin bool) *syscall.SysProcAttr {
	u, g := IDs()
	if u < 0 {
		return nil
	}
	caps := []uintptr{capNetBindService}
	if netAdmin {
		caps = append(caps, capNetAdmin)
	}
	return &syscall.SysProcAttr{
		Credential:  &syscall.Credential{Uid: uint32(u), Gid: uint32(g)},
		AmbientCaps: caps,
	}
}
