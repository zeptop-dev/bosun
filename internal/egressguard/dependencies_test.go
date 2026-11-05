package egressguard

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestMissingNFTCanBeDetectedAfterInstall(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	g := &Guard{}
	if got := g.MissingTools(); !reflect.DeepEqual(got, []string{"nft"}) {
		t.Fatalf("missing: %v", got)
	}
	if err := g.Apply(context.Background(), 900, Options{}); err == nil {
		t.Fatal("missing nft accepted")
	}
	if got := g.Status(); got.Supported || !reflect.DeepEqual(got.MissingTools, []string{"nft"}) {
		t.Fatalf("status: %+v", got)
	}
	if err := os.WriteFile(filepath.Join(dir, "nft"), []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if got := g.MissingTools(); len(got) != 0 {
		t.Fatalf("dependency detection remained stale: %v", got)
	}
}
