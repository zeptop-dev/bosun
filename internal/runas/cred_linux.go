//go:build linux

package runas

import "syscall"

// Credential is the SysProcAttr that runs a child as the core account with
// only CAP_NET_BIND_SERVICE (ports below 1024); nil when none is set.
func Credential() *syscall.SysProcAttr {
	u, g := IDs()
	if u < 0 {
		return nil
	}
	const capNetBindService, capNetAdmin = 10, 12
	caps := []uintptr{capNetBindService}
	if NetAdmin() {
		// SO_MARK (the per-user speed-limit marks) needs CAP_NET_ADMIN.
		caps = append(caps, capNetAdmin)
	}
	return &syscall.SysProcAttr{
		Credential:  &syscall.Credential{Uid: uint32(u), Gid: uint32(g), NoSetGroups: true},
		AmbientCaps: caps,
	}
}
