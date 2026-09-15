package local

import "time"

// Device limits and quota cycles for the standalone store. Callers hold s.mu.

const (
	// deviceWindow is how long a client IP counts as "online" after it was
	// last reported; deviceHold is how long an offending user stays off the
	// node once the limit is exceeded (long enough for the extra clients to
	// give up, short enough to self-heal).
	deviceWindow = 3 * time.Minute
	deviceHold   = 5 * time.Minute
)

// enforceDevices folds the latest online report into the per-user IP
// history and holds back users above their limit. It reports whether the
// rendered user list changed (a hold started or ended).
func (s *Store) enforceDevices(now time.Time) bool {
	if s.seenIPs == nil {
		s.seenIPs = map[string]map[string]time.Time{}
	}
	if s.overDevices == nil {
		s.overDevices = map[int64]time.Time{}
	}
	for name, ips := range s.online {
		m := s.seenIPs[name]
		if m == nil {
			m = map[string]time.Time{}
			s.seenIPs[name] = m
		}
		for _, ip := range ips {
			m[ip] = now
		}
	}
	changed := false
	for _, u := range s.st.Users {
		if u.DeviceLimit <= 0 {
			continue
		}
		m := s.seenIPs[u.UUID]
		n := 0
		for ip, at := range m {
			if now.Sub(at) > deviceWindow {
				delete(m, ip)
				continue
			}
			n++
		}
		if n > u.DeviceLimit && !s.overDevices[u.ID].After(now) {
			s.overDevices[u.ID] = now.Add(deviceHold)
			changed = true
		}
	}
	for id, until := range s.overDevices {
		if !until.After(now) {
			delete(s.overDevices, id)
			// Forget the IPs too, or the same set re-triggers at once.
			for _, u := range s.st.Users {
				if u.ID == id {
					delete(s.seenIPs, u.UUID)
				}
			}
			changed = true
		}
	}
	return changed
}

// resetQuotasDue zeroes counters whose cycle has come round. Only users
// that were blocked by their quota change the rendered list.
func (s *Store) resetQuotasDue(now time.Time) bool {
	changed := false
	for i := range s.st.Users {
		u := &s.st.Users[i]
		if u.ResetMode == "" {
			u.ResetAt = nil
			continue
		}
		if u.ResetAt == nil {
			u.ResetAt = u.NextReset(now)
			continue
		}
		if now.Before(*u.ResetAt) {
			continue
		}
		wasUsable := u.Usable(now)
		u.Up, u.Down = 0, 0
		u.ResetAt = u.NextReset(*u.ResetAt)
		for u.ResetAt != nil && !now.Before(*u.ResetAt) {
			u.ResetAt = u.NextReset(*u.ResetAt)
		}
		if u.Usable(now) != wasUsable {
			changed = true
		}
	}
	return changed
}
