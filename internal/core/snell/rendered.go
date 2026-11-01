package snell

import (
	"github.com/zeptop-dev/bosun/internal/core"
	"github.com/zeptop-dev/bosun/pkg/agentproto"
)

// RenderedConfig returns evidence only for the supervised generations that
// successfully accepted these activation files. Automatic restarts cannot
// inherit an old observation, even if their PID or file path is reused.
func (c *Core) RenderedConfig() *agentproto.RenderedArtifact {
	return c.rendered.Snapshot(c.Name(), core.RenderedProcesses(c))
}
