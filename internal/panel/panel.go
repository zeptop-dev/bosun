// Package panel defines the driver interface between bosun and a management
// panel. Bosun pulls desired state from the panel and pushes accounting back.
package panel

import (
	"context"

	"gitlab.com/zeptop-group/bosun/internal/spec"
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
