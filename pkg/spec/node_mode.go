package spec

import "errors"

// NodeMode is independent of the panel driver. Empty retains legacy full mode.
type NodeMode string

const NodeModeMinVersion = "v0.66.0"

const (
	NodeFull    NodeMode = "full"
	NodeMonitor NodeMode = "monitor"
)

func (m NodeMode) Effective() NodeMode {
	if m == "" {
		return NodeFull
	}
	return m
}

func (m NodeMode) Validate() error {
	if m.Effective() != NodeFull && m != NodeMonitor {
		return errors.New("invalid node mode")
	}
	return nil
}

var ErrMonitorOnly = errors.New("monitor-only nodes cannot manage proxy services; switch to full mode first")

// ValidateMonitorState prevents side effects before certificates, cores or
// forwarding are touched. Monitoring configuration lives outside Node.
func ValidateMonitorState(n *Node, users []User, forwards []Forward) error {
	if n == nil {
		return nil
	}
	if n.ServiceControl != nil && n.ServiceControl.Mode != ServiceControlNormal {
		return ErrMonitorOnly
	}
	if len(n.WireGuardLinks)+len(n.Inbounds)+len(n.Outbounds)+len(n.Routes)+len(n.Forwards)+len(n.ReverseClients)+len(n.Overrides)+len(n.EgressUpstreams)+len(n.Certificates)+len(users)+len(forwards) > 0 || n.Decoy != nil || n.ACME != nil || n.DefaultOutbound != "" || n.UserSpeedLimitMbps != 0 || n.AllowPrivateDest || len(n.PrivateDestAllow) > 0 || n.EgressByIngress || len(n.AuditRules) > 0 || len(n.DNS) > 0 || n.ConnLog {
		return ErrMonitorOnly
	}
	return nil
}
