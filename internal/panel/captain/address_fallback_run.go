package captain

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"time"

	"github.com/zeptop-dev/bosun/pkg/agentproto"
)

// The sampler, rather than the report loop, tracks continuity: a failed sample
// overwritten before the next report must still break panel confirmation.
type addressFallbackRuns struct {
	v4, v6 addressFallbackRun
	newID  func() (string, error)
}

type addressFallbackRun struct {
	id, address, source, origin string
	sampledAt                   int64
	observedAt                  time.Time
}

func (runs *addressFallbackRuns) annotate(sample *agentproto.PublicAddresses, complete bool, at time.Time) {
	newID := runs.newID
	if newID == nil {
		newID = newAddressFallbackRunID
	}
	sample.FallbackIPv4 = runs.v4.advance(sample.FallbackIPv4, sample.IPv4, sample.SampledAt, false, complete, at, newID)
	sample.FallbackIPv6 = runs.v6.advance(sample.FallbackIPv6, sample.IPv6, sample.SampledAt, true, complete, at, newID)
}

func (run *addressFallbackRun) advance(in *agentproto.PublicAddressFallback, primary string, sampledAt int64, v6, complete bool, at time.Time, newID func() (string, error)) *agentproto.PublicAddressFallback {
	if in == nil {
		*run = addressFallbackRun{}
		return nil
	}
	// Reports may still be sending a previous observation. Never mutate it or
	// accept a caller-supplied run identity as sampler evidence.
	out := *in
	out.RunID = ""
	if !complete || primary != "" || in.Error != "" || in.CheckStatus != agentproto.PublicAddressFallbackCheckNoConflict ||
		in.Source != agentproto.PublicAddressFallbackSource || in.Origin == "" || !agentproto.ValidPublicAddress(in.Address, v6) ||
		in.SampledAt <= 0 || in.SampledAt > sampledAt || sampledAt-in.SampledAt > 60 {
		*run = addressFallbackRun{}
		return &out
	}
	if run.id == "" || run.address != in.Address || run.source != in.Source || run.origin != in.Origin ||
		in.SampledAt <= run.sampledAt || in.SampledAt-run.sampledAt > 900 || at.Before(run.observedAt) || at.Sub(run.observedAt) > 15*time.Minute {
		*run = addressFallbackRun{}
		id, err := newID()
		if err != nil || id == "" {
			return &out
		}
		run.id = id
	}
	run.address, run.source, run.origin = in.Address, in.Source, in.Origin
	run.sampledAt, run.observedAt = in.SampledAt, at
	out.RunID = run.id
	return &out
}

func newAddressFallbackRunID() (string, error) {
	var value [16]byte
	if _, err := io.ReadFull(rand.Reader, value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}
