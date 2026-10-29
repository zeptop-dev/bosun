package main

import "testing"

func TestUpdaterKeepsOfflineRecoveryAndControlCompatibilityFloor(t *testing.T) {
	for _, tc := range []struct{ configured, want string }{
		{"", "v0.84.0"}, {"invalid", "v0.84.0"}, {"v0.66.0", "v0.84.0"},
		{"v0.75.0", "v0.84.0"}, {"v0.76.1", "v0.84.0"}, {"v0.77.0", "v0.84.0"},
		{"v0.78.0", "v0.84.0"}, {"v0.82.0", "v0.84.0"}, {"v0.83.0", "v0.84.0"},
		{"v0.84.0", "v0.84.0"}, {"v0.85.0", "v0.85.0"},
	} {
		if got := newUpdater(tc.configured).MinVersion; got != tc.want {
			t.Fatalf("floor %q: %s", tc.configured, got)
		}
	}
}
