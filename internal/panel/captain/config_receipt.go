package captain

import (
	"github.com/zeptop-dev/bosun/internal/panel"
)

func (c *Client) configStateLocked() panel.ConfigState {
	if c.state == nil {
		return panel.ConfigState{}
	}
	s := panel.ConfigState{ConfigRevision: c.state.ConfigRevision, StateRevision: c.state.Revision, Online: !c.offline && !c.revoked && !c.configRejected}
	if d := c.state.ConfigDelivery; d != nil && d.Session == c.configSession && d.ID != "" {
		s.Session, s.DeliveryID = d.Session, d.ID
	}
	return s
}

func (c *Client) ConsumedConfig() (session string, nodeUsers, forwards panel.ConfigState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.configRejected || c.revoked {
		return c.configSession, panel.ConfigState{}, panel.ConfigState{}
	}
	if c.nodeConfig == c.usersConfig {
		nodeUsers = c.nodeConfig
	}
	return c.configSession, nodeUsers, c.forwardConfig
}
