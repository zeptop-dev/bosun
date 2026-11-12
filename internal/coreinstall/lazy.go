package coreinstall

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// LazyBinary prepares an on-demand forwarding backend without blocking the
// caller's reconciliation loop. It holds no forwarding configuration and never
// starts a process. lifetime is the owning agent's lifetime, not an apply timeout.
func (i *Installer) LazyBinary(lifetime context.Context, name, version string) func(context.Context) (string, error) {
	var mu sync.Mutex
	var busy bool
	var next time.Time
	var attempts uint
	last := fmt.Errorf("%s binary is being prepared", name)
	return func(ctx context.Context) (string, error) {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if err := lifetime.Err(); err != nil {
			return "", err
		}
		rel, ok := Resolve(name, version)
		if version == "" {
			rel, ok = Default(name)
		}
		if !ok {
			return "", fmt.Errorf("unknown core %s %s", name, version)
		}
		if i.Installed(name, rel.Version) {
			return i.Path(name, rel.Version), nil
		}
		mu.Lock()
		defer mu.Unlock()
		if !busy && !time.Now().Before(next) {
			busy = true
			go func() {
				work, cancel := context.WithTimeout(lifetime, 10*time.Minute)
				defer cancel()
				_, err := i.Ensure(work, name, rel.Version)
				mu.Lock()
				defer mu.Unlock()
				busy = false
				if err == nil {
					attempts = 0
					return
				}
				last = err
				if attempts < 5 {
					attempts++
				}
				next = time.Now().Add(30 * time.Second * time.Duration(1<<(attempts-1)))
			}()
		}
		return "", last
	}
}
