package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/zeptop-dev/bosun/internal/warp"
	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

// resolveWARP fills from_node WARP outbounds with the node's account so the
// cores see plain WireGuard credentials.
func (a *Agent) resolveWARP(node spec.Node) (spec.Node, error) {
	acct := a.warpAccount()
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
	jctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	acct, err := (&warp.Client{}).Register(jctx, p.License)
	if acct != nil {
		if serr := a.saveWARP(acct); serr != nil {
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

// warpFile keeps the account on a panel-managed node, which has no local
// store: the private key never leaves the box, the panel only sees the
// public part in the job result.
func (a *Agent) warpFile() string { return filepath.Join(a.cfg.DataDir, "warp.json") }

func (a *Agent) warpAccount() *spec.WARPAccount {
	if a.WARPAccount != nil {
		return a.WARPAccount()
	}
	b, err := os.ReadFile(a.warpFile())
	if err != nil {
		return nil
	}
	var acct spec.WARPAccount
	if json.Unmarshal(b, &acct) != nil || acct.PrivateKey == "" {
		return nil
	}
	return &acct
}

func (a *Agent) saveWARP(acct *spec.WARPAccount) error {
	if a.SaveWARP != nil {
		return a.SaveWARP(acct)
	}
	b, err := json.MarshalIndent(acct, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(a.cfg.DataDir, 0o750); err != nil {
		return err
	}
	return os.WriteFile(a.warpFile(), b, 0o600)
}
