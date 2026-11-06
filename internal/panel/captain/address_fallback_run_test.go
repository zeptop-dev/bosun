package captain

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/zeptop-dev/bosun/pkg/agentproto"
)

func fallbackSample(at time.Time) agentproto.PublicAddresses {
	return agentproto.PublicAddresses{SampledAt: at.Unix(), FallbackIPv4: &agentproto.PublicAddressFallback{
		Address: "198.51.100.20", Source: agentproto.PublicAddressFallbackSource, Origin: "https://example.com:2096",
		SampledAt: at.Unix(), CheckStatus: agentproto.PublicAddressFallbackCheckNoConflict,
	}, FallbackIPv6: &agentproto.PublicAddressFallback{
		Address: "2001:db8::10", Source: agentproto.PublicAddressFallbackSource, Origin: "https://example.com:2096",
		SampledAt: at.Unix(), CheckStatus: agentproto.PublicAddressFallbackCheckNoConflict,
	}}
}

func assertFallbackRunID(t *testing.T, id string) {
	t.Helper()
	if value, err := hex.DecodeString(id); err != nil || len(value) != 16 {
		t.Fatalf("invalid 128-bit run identity %q", id)
	}
}

func TestFallbackSamplerContinuitySurvivesReportIntervals(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := &Client{cfg: Config{URL: "https://example.com:2096"}, stop: make(chan struct{})}
		readSample := func(c *Client) *agentproto.PublicAddresses {
			c.mu.Lock()
			defer c.mu.Unlock()
			return c.addresses
		}
		stop := func(c *Client) {
			select {
			case <-c.stop:
			default:
				close(c.stop)
			}
		}
		defer stop(c)
		var calls atomic.Int32
		go c.watchAddressSamples(func(context.Context) agentproto.PublicAddresses {
			call := calls.Add(1)
			sample := fallbackSample(time.Now())
			if call == 2 {
				sample.FallbackIPv4 = nil // failure hidden between two minute-spaced reports
			}
			return sample
		})
		synctest.Wait()
		first := readSample(c)
		assertFallbackRunID(t, first.FallbackIPv4.RunID)
		assertFallbackRunID(t, first.FallbackIPv6.RunID)
		time.Sleep(time.Minute)
		synctest.Wait()
		third := readSample(c)
		if calls.Load() != 3 || first.FallbackIPv4.RunID == third.FallbackIPv4.RunID || first.FallbackIPv6.RunID != third.FallbackIPv6.RunID {
			t.Fatalf("hidden failure crossed report interval, or family runs interfered: calls=%d first=%+v next=%+v", calls.Load(), first, third)
		}
		assertFallbackRunID(t, third.FallbackIPv4.RunID)
		time.Sleep(30 * time.Second)
		synctest.Wait()
		fourth := readSample(c)
		if third.FallbackIPv4.RunID != fourth.FallbackIPv4.RunID || third.SampledAt == fourth.SampledAt {
			t.Fatal("successful later sample did not retain its run with a new timestamp")
		}
		stop(c)
		synctest.Wait()
		// Restarting the sampler is a new identity even with the same address.
		restarted := &Client{cfg: c.cfg, stop: make(chan struct{})}
		defer stop(restarted)
		go restarted.watchAddressSamples(func(context.Context) agentproto.PublicAddresses { return fallbackSample(time.Now()) })
		synctest.Wait()
		if readSample(restarted).FallbackIPv4.RunID == fourth.FallbackIPv4.RunID {
			t.Fatal("sampler restart reused confirmation identity")
		}
		stop(restarted)
		synctest.Wait()
	})
}

func TestFallbackRunBreaksOnEveryInvalidatingEvent(t *testing.T) {
	for _, event := range []string{"error", "conflict", "old agent", "primary recovered", "wrong source", "address", "origin", "gap", "duplicate", "clock regression", "cancelled", "wrong family"} {
		t.Run(event, func(t *testing.T) {
			at := time.Unix(1_800_000_000, 0)
			var runs addressFallbackRuns
			first := fallbackSample(at)
			runs.annotate(&first, true, at)
			assertFallbackRunID(t, first.FallbackIPv4.RunID)
			at = at.Add(30 * time.Second)
			broken := fallbackSample(at)
			complete := true
			switch event {
			case "error":
				broken.FallbackIPv4.Error = "network"
			case "conflict":
				broken.FallbackIPv4.CheckStatus = agentproto.PublicAddressFallbackCheckConflict
			case "old agent":
				broken.FallbackIPv4.CheckStatus = ""
			case "primary recovered":
				broken.IPv4 = "198.51.100.20"
			case "wrong source":
				broken.FallbackIPv4.Source = "unrecognized"
			case "address":
				broken.FallbackIPv4.Address = "203.0.113.30"
			case "origin":
				broken.FallbackIPv4.Origin = "https://example.com:8443"
			case "gap":
				at = at.Add(16 * time.Minute)
				broken = fallbackSample(at)
			case "duplicate":
				broken = fallbackSample(at.Add(-30 * time.Second))
			case "clock regression":
				at = at.Add(-time.Minute)
				broken = fallbackSample(at)
			case "cancelled":
				complete = false
			case "wrong family":
				broken.FallbackIPv4.Address = "2001:db8::10"
			}
			runs.annotate(&broken, complete, at)
			if broken.FallbackIPv4.RunID == first.FallbackIPv4.RunID {
				t.Fatal("invalidating event retained prior run")
			}
			at = at.Add(30 * time.Second)
			next := fallbackSample(at)
			runs.annotate(&next, true, at)
			assertFallbackRunID(t, next.FallbackIPv4.RunID)
			if next.FallbackIPv4.RunID == first.FallbackIPv4.RunID {
				t.Fatal("recovery revived prior run")
			}
		})
	}
}

func TestFallbackRunEntropyFailureAndImmutability(t *testing.T) {
	at := time.Unix(1_800_000_000, 0)
	runs := addressFallbackRuns{newID: func() (string, error) { return "", errors.New("no entropy") }}
	sample := fallbackSample(at)
	old := sample.FallbackIPv4
	old.RunID = "not-sampler-evidence"
	runs.annotate(&sample, true, at)
	if sample.FallbackIPv4.RunID != "" || sample.FallbackIPv6.RunID != "" || old.RunID != "not-sampler-evidence" {
		t.Fatal("entropy failure supplied evidence or changed an in-flight report")
	}
	runs.newID = nil
	at = at.Add(30 * time.Second)
	next := fallbackSample(at)
	runs.annotate(&next, true, at)
	assertFallbackRunID(t, next.FallbackIPv4.RunID)
	if sample.FallbackIPv4.RunID != "" {
		t.Fatal("later success changed a previous report")
	}
}

func TestFallbackFollowContractExport(t *testing.T) {
	samples := []agentproto.PublicAddresses{
		fallbackSample(time.Unix(1_800_000_000, 0)), fallbackSample(time.Unix(1_800_000_120, 0)),
		fallbackSample(time.Unix(1_800_000_240, 0)), fallbackSample(time.Unix(1_800_000_360, 0)),
		fallbackSample(time.Unix(1_800_000_480, 0)),
	}
	samples[2].FallbackIPv4.CheckStatus = agentproto.PublicAddressFallbackCheckConflict
	if path := os.Getenv("BOSUN_ADDRESS_CONTRACT_RAW"); path != "" {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(body, &samples); err != nil {
			t.Fatal(err)
		}
	}
	var runs addressFallbackRuns
	var reports []agentproto.Report
	for i := range samples {
		runs.annotate(&samples[i], true, time.Unix(samples[i].SampledAt, 0))
		reports = append(reports, agentproto.Report{PublicAddresses: &samples[i]})
	}
	if len(samples) != 5 || samples[0].FallbackIPv4.RunID == "" || samples[0].FallbackIPv4.RunID != samples[1].FallbackIPv4.RunID || samples[2].FallbackIPv4.RunID != "" || samples[3].FallbackIPv4.RunID == "" || samples[3].FallbackIPv4.RunID == samples[0].FallbackIPv4.RunID || samples[3].FallbackIPv4.RunID != samples[4].FallbackIPv4.RunID {
		t.Fatal("exported fixture violates continuity contract")
	}
	if path := os.Getenv("BOSUN_ADDRESS_CONTRACT_OUT"); path != "" {
		body, err := json.MarshalIndent(reports, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
