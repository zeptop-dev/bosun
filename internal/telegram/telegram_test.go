package telegram

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestStatusAndNotify(t *testing.T) {
	var mu sync.Mutex
	var sent []string
	served := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/getUpdates"):
			if served {
				time.Sleep(50 * time.Millisecond)
				_, _ = w.Write([]byte(`{"ok":true,"result":[]}`))
				return
			}
			served = true
			_, _ = w.Write([]byte(`{"ok":true,"result":[{"update_id":1,"message":{"text":"/status","chat":{"id":42}}},{"update_id":2,"message":{"text":"/id","chat":{"id":7}}}]}`))
		case strings.HasSuffix(r.URL.Path, "/sendMessage"):
			var in map[string]any
			_ = json.NewDecoder(r.Body).Decode(&in)
			mu.Lock()
			sent = append(sent, in["text"].(string))
			mu.Unlock()
			_, _ = w.Write([]byte(`{"ok":true,"result":{}}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	APIBase = srv.URL
	b := &Bot{Settings: func() Settings { return Settings{Token: "t", ChatID: 42, Notify: true} }, Status: func(context.Context) string { return "all good" }, PollTimeout: 1}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go b.Run(ctx)
	if err := b.Notify(ctx, "alert"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(600 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	joined := strings.Join(sent, "|")
	if !strings.Contains(joined, "alert") || !strings.Contains(joined, "all good") || !strings.Contains(joined, "<code>7</code>") {
		t.Fatalf("sent: %v", sent)
	}
}
