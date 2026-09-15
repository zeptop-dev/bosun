package agent

import (
	"context"
	"encoding/json"
	"time"

	"github.com/zeptop-dev/bosun/internal/warp"
	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

// resolveWARP fills from_node WARP outbounds with the node's account so the
// cores see plain WireGuard credentials.
func (a *Agent) resolveWARP(node spec.Node) (spec.Node, error) {
	var acct *spec.WARPAccount
	if a.WARPAccount != nil {
		acct = a.WARPAccount()
	}
	outs := make([]spec.Outbound, 0, len(node.Outbounds))
	for _, o := range node.Outbounds {
		r, err := warp.Resolve(o, acct)
		if err != nil {
			return node, err
		}
		outs = append(outs, r)
	}
	node.Outbounds = outs
	return node, nil
}

// warpRegisterJob is the panel-driven registration: the node keeps the
// keys and reports the public part.
func (a *Agent) warpRegisterJob(ctx context.Context, params json.RawMessage) agentproto.JobResult {
	var p struct {
		License string `json:"license"`
	}
	_ = json.Unmarshal(params, &p)
	out := agentproto.JobResult{Kind: "warp_register"}
	if a.SaveWARP == nil {
		out.Error = "no local store to keep the WARP account"
		return out
	}
	jctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	acct, err := (&warp.Client{}).Register(jctx, p.License)
	if acct != nil {
		if serr := a.SaveWARP(acct); serr != nil {
			out.Error = serr.Error()
			return out
		}
		out.Result, _ = json.Marshal(warp.Public(acct))
		select {
		case a.kick <- struct{}{}:
		default:
		}
	}
	if err != nil {
		out.Error = err.Error()
	}
	return out
}
