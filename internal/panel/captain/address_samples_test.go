package captain

import (
	"context"
	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestAddressSamplingWarmupAndShutdown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := &Client{stop: make(chan struct{})}
		var calls atomic.Int32
		go c.watchAddressSamples(func(context.Context) agentproto.PublicAddresses {
			calls.Add(1)
			return agentproto.PublicAddresses{SampledAt: time.Now().Unix(), IPv4: "198.51.100.20"}
		})
		synctest.Wait()
		if calls.Load() != 1 {
			t.Fatal("startup sample missing")
		}
		c.mu.Lock()
		first := c.addresses.SampledAt
		c.mu.Unlock()
		time.Sleep(time.Minute)
		synctest.Wait()
		c.mu.Lock()
		next := c.addresses.SampledAt
		c.mu.Unlock()
		if calls.Load() < 3 || next-first < 30 {
			t.Fatal("minute-spaced reports cannot receive independent warmup samples")
		}
		time.Sleep(2 * time.Minute)
		synctest.Wait()
		atEnd := calls.Load()
		time.Sleep(4 * time.Minute)
		synctest.Wait()
		if calls.Load() != atEnd {
			t.Fatal("startup probing continued into steady state")
		}
		time.Sleep(time.Minute)
		synctest.Wait()
		if calls.Load() != atEnd+1 {
			t.Fatal("steady-state sample missing")
		}
		close(c.stop)
		synctest.Wait()
		time.Sleep(10 * time.Minute)
		if calls.Load() != atEnd+1 {
			t.Fatal("sampling continued after shutdown")
		}
	})
}

func TestAddressSamplingCancelsInflightProbe(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := &Client{stop: make(chan struct{})}
		done := make(chan struct{})
		go func() {
			defer close(done)
			c.watchAddressSamples(func(ctx context.Context) agentproto.PublicAddresses {
				<-ctx.Done()
				return agentproto.PublicAddresses{}
			})
		}()
		synctest.Wait()
		close(c.stop)
		synctest.Wait()
		select {
		case <-done:
		default:
			t.Fatal("shutdown did not cancel the probe")
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.addresses != nil {
			t.Fatal("cancelled probe published an observation")
		}
	})
}

func TestAddressSamplingDoesNotPublishAfterOriginChange(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := &Client{cfg: Config{URL: "https://example.com:2096"}, stop: make(chan struct{})}
		go c.watchAddressSamples(func(context.Context) agentproto.PublicAddresses {
			c.cfg.URL = "https://example.com:443"
			return agentproto.PublicAddresses{SampledAt: time.Now().Unix(), FallbackIPv4: &agentproto.PublicAddressFallback{Address: "198.51.100.20", Origin: "https://example.com:2096"}}
		})
		synctest.Wait()
		close(c.stop)
		synctest.Wait()
		if c.addresses != nil {
			t.Fatal("observation crossed connection epoch")
		}
	})
}
