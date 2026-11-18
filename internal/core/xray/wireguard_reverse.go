package xray

import (
	"github.com/zeptop-dev/bosun/internal/core"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

func wireGuardRoutes(node *spec.Node, inbounds []spec.Inbound, users []spec.User) ([]any, []any, error) {
	return core.WireGuardRoutes("xray", node, inbounds, users)
}
