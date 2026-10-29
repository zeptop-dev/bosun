package spec

import (
	"errors"
	"regexp"
)

const (
	ServiceControlNormal = "normal"
	ServiceControlLimit  = "limit"
	ServiceControlPause  = "pause"
	// ServiceControlSocketMark identifies only bosun's in-process relay sockets.
	// It is outside private-access's 0x40000000..0x7fffffff allocation. Agents
	// also reject a legacy per-user speed mark collision before enabling control.
	ServiceControlSocketMark = 0xb0500001
)

// ServiceControl is a resolved server policy, not a user quota. LimitMbps is
// the aggregate upload-plus-download rate of managed proxy packets emitted or
// forwarded by this host. Linux enforces a byte policer, not a smooth queue.
// A missing value preserves normal operation. Revision identifies the policy
// generation independently from frequent host-traffic samples.
type ServiceControl struct {
	Offline   *OfflineServiceControl `json:"offline,omitempty"`
	Revision  string                 `json:"revision"`
	Mode      string                 `json:"mode"`
	LimitMbps int                    `json:"limit_mbps,omitempty"`
}

var serviceControlRevision = regexp.MustCompile(`^[a-zA-Z0-9._:-]{1,128}$`)

func (s *ServiceControl) Validate() error {
	if s == nil {
		return nil
	}
	if !serviceControlRevision.MatchString(s.Revision) {
		return errors.New("invalid service control revision")
	}
	switch s.Mode {
	case ServiceControlNormal, ServiceControlPause:
		if s.LimitMbps != 0 {
			return errors.New("service control limit is only valid in limit mode")
		}
	case ServiceControlLimit:
		if s.LimitMbps < 1 || s.LimitMbps > 1000000 {
			return errors.New("service control limit must be between 1 and 1000000 Mbps")
		}
	default:
		return errors.New("invalid service control mode")
	}
	return s.Offline.Validate()
}
