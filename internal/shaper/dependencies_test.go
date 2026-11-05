package shaper

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestMissingToolsIncludesAlpineTCAndIP(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	s := &Shaper{}
	if got := s.MissingTools(); !reflect.DeepEqual(got, []string{"nft", "tc", "ip"}) {
		t.Fatalf("missing: %v", got)
	}
	for _, name := range []string{"nft", "ip"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if got := s.MissingTools(); !reflect.DeepEqual(got, []string{"tc"}) {
		t.Fatalf("installing nft alone must not imply tc available: %v", got)
	}
	if err := s.Apply(context.Background(), []Limit{{UserID: 7, Mbps: 2}}); err == nil {
		t.Fatal("missing tc accepted")
	}
	if got := s.Status(); got.Supported || !reflect.DeepEqual(got.MissingTools, []string{"tc"}) {
		t.Fatalf("status: %+v", got)
	}
	if err := os.WriteFile(filepath.Join(dir, "tc"), []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if got := s.MissingTools(); len(got) != 0 {
		t.Fatalf("dependency detection remained stale: %v", got)
	}
}
