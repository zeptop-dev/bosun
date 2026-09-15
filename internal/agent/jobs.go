package agent

import (
	"context"
	"encoding/json"
	"time"

	"github.com/zeptop-dev/bosun/internal/panel"
	"github.com/zeptop-dev/bosun/internal/realityscan"
	"github.com/zeptop-dev/bosun/pkg/agentproto"
)

// runJobs starts every job in the panel's state that has not run yet. Each
// runs in its own goroutine; its result is queued for the next report and
// an out-of-band report is requested so the panel sees it within seconds.
func (a *Agent) runJobs(ctx context.Context) {
	src, ok := a.driver.(panel.JobSource)
	if !ok {
		return
	}
	jobs := src.Jobs()
	current := map[string]bool{}
	for _, j := range jobs {
		current[j.ID] = true
	}
	a.jobsMu.Lock()
	// Forget finished jobs the panel already dropped so the set stays small.
	for id := range a.jobsDone {
		if !current[id] {
			delete(a.jobsDone, id)
		}
	}
	var start []agentproto.Job
	for _, j := range jobs {
		if a.jobsDone[j.ID] || a.jobsRunning[j.ID] {
			continue
		}
		a.jobsRunning[j.ID] = true
		start = append(start, j)
	}
	a.jobsMu.Unlock()
	for _, j := range start {
		go func(j agentproto.Job) {
			a.log.Info("job started", "id", j.ID, "kind", j.Kind)
			res := a.execJob(ctx, j)
			a.jobsMu.Lock()
			delete(a.jobsRunning, j.ID)
			a.jobsDone[j.ID] = true
			a.jobResults = append(a.jobResults, res)
			a.jobsMu.Unlock()
			a.log.Info("job finished", "id", j.ID, "kind", j.Kind, "error", res.Error)
			select {
			case a.reportNow <- struct{}{}:
			default:
			}
		}(j)
	}
}

func (a *Agent) execJob(ctx context.Context, j agentproto.Job) agentproto.JobResult {
	out := agentproto.JobResult{ID: j.ID, Kind: j.Kind}
	switch j.Kind {
	case "reality_scan":
		var p struct {
			Hosts []string `json:"hosts"`
			Port  int      `json:"port"`
		}
		_ = json.Unmarshal(j.Params, &p)
		jctx, cancel := context.WithTimeout(ctx, 90*time.Second)
		defer cancel()
		res := realityscan.Scan(jctx, p.Hosts, realityscan.Options{Port: p.Port})
		out.Result, _ = json.Marshal(res)
	case "warp_register":
		r := a.warpRegisterJob(ctx, j.Params)
		out.Result, out.Error = r.Result, r.Error
	default:
		out.Error = "unknown job kind " + j.Kind
	}
	return out
}

// takeJobResults hands the queued results to a report.
func (a *Agent) takeJobResults() []agentproto.JobResult {
	a.jobsMu.Lock()
	defer a.jobsMu.Unlock()
	out := a.jobResults
	a.jobResults = nil
	return out
}

// requeueJobResults puts results back after a failed report.
func (a *Agent) requeueJobResults(rs []agentproto.JobResult) {
	if len(rs) == 0 {
		return
	}
	a.jobsMu.Lock()
	a.jobResults = append(rs, a.jobResults...)
	a.jobsMu.Unlock()
}
