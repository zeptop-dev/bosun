package captain

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/agentproto"
)

func TestAddressReportIsBoundToSampleOrigin(t *testing.T) {
	reports := make(chan agentproto.Report, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var report agentproto.Report
		if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
			t.Error(err)
		}
		reports <- report
		json.NewEncoder(w).Encode(agentproto.ReportResponse{})
	}))
	defer srv.Close()
	sample := &agentproto.PublicAddresses{SampledAt: time.Now().Unix(), FallbackIPv4: &agentproto.PublicAddressFallback{Address: "198.51.100.20", Source: agentproto.PublicAddressFallbackSource, Origin: "https://example.com:2096", SampledAt: time.Now().Unix(), CheckStatus: agentproto.PublicAddressFallbackCheckNoConflict, RunID: "b0123456789012345678901234567890b"}}
	c := &Client{cfg: Config{URL: srv.URL}, http: srv.Client(), token: "test-token", addresses: sample, addressesURL: srv.URL}
	if _, err := c.Report(context.Background(), agentproto.Report{}); err != nil {
		t.Fatal(err)
	}
	got := <-reports
	if got.PublicAddresses == nil || got.PublicAddresses.IPv4 != "" || got.PublicAddresses.FallbackIPv4 == nil || *got.PublicAddresses.FallbackIPv4 != *sample.FallbackIPv4 {
		t.Fatal("fallback contract lost in real report")
	}
	c.addressesURL = "https://example.com:2096"
	if _, err := c.Report(context.Background(), agentproto.Report{PublicAddresses: sample}); err != nil {
		t.Fatal(err)
	}
	if got := <-reports; got.PublicAddresses != nil {
		t.Fatal("old origin addresses reached a new panel connection")
	}
}
