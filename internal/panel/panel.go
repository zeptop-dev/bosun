// Package panel defines the driver interface between bosun and a management
// panel. Bosun pulls desired state from the panel and pushes accounting back.
package panel

import (
	"context"

	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

// Driver talks to one panel implementation.
//
// Node and Users return changed=false when the panel reports no change since
// the previous call (e.g. via ETag); the returned value is then nil.
type Driver interface {
	Name() string
	Node(ctx context.Context) (node *spec.Node, changed bool, err error)
	Users(ctx context.Context) (users []spec.User, changed bool, err error)
	PushTraffic(ctx context.Context, traffic []spec.UserTraffic) error
	PushStatus(ctx context.Context, status spec.SystemStatus) error
	Intervals() spec.Intervals
}

// ForwardSource is implemented by drivers whose panel manages forwarding
// rules. Drivers without it (Xboard) leave forwards to the local config.
type ForwardSource interface {
	Forwards(ctx context.Context) (forwards []spec.Forward, changed bool, err error)
}

// Notifier is implemented by drivers that can wake the agent when desired
// state changes (the local store does this on every edit), so changes apply
// at once instead of on the next pull tick.
type Notifier interface {
	Changed() <-chan struct{}
}

// Reporter is implemented by drivers that accept one combined report per
// push interval (traffic, host status, forward probes, core state). The
// agent prefers it over PushTraffic/PushStatus. stateChanged asks the agent
// to pull immediately.
type Reporter interface {
	Report(ctx context.Context, rep agentproto.Report) (stateChanged bool, err error)
}
