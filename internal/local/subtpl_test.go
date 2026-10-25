package local

import (
	"log/slog"
	"os"
	"reflect"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/subdesign"
)

func TestApplySubDesignPersistsSelectionTogether(t *testing.T) {
	s := openTest(t)
	old := subdesign.Design{Final: "DIRECT"}
	if err := s.SetSubDesign(old); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSubTemplates(map[string]string{"clash": "old-clash", "qx": "manual-qx"}); err != nil {
		t.Fatal(err)
	}
	updated := subdesign.Design{Final: "REJECT"}
	if err := s.ApplySubDesign(updated, map[string]string{"clash": "new-clash", "stash": "new-stash"}); err != nil {
		t.Fatal(err)
	}
	reopened, _, err := Open(s.Path(), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(reopened.SubDesign(), updated) || reopened.SubTemplate("clash") != "new-clash" || reopened.SubTemplate("stash") != "new-stash" || reopened.SubTemplate("qx") != "manual-qx" {
		t.Fatal("draft and selected templates were not persisted together, or an unselected template changed")
	}
}

func TestApplySubDesignFailedWriteRetainsPreviousState(t *testing.T) {
	s := openTest(t)
	old := subdesign.Design{Final: "DIRECT"}
	if err := s.SetSubDesign(old); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSubTemplates(map[string]string{"clash": "manual-clash", "qx": "manual-qx"}); err != nil {
		t.Fatal(err)
	}
	originalPath := s.path
	originalTemplates := s.SubTemplates()
	originalBytes, err := os.ReadFile(originalPath)
	if err != nil {
		t.Fatal(err)
	}
	// A directory at the target reliably forces atomic rename to fail,
	// including under privileged test runners where chmod is ineffective.
	s.path = originalPath + ".blocked"
	if err := os.Mkdir(s.path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.ApplySubDesign(subdesign.Design{Final: "REJECT"}, map[string]string{"clash": "new-clash"}); err == nil {
		t.Fatal("expected write failure")
	}
	if !reflect.DeepEqual(s.SubDesign(), old) || !reflect.DeepEqual(s.SubTemplates(), originalTemplates) {
		t.Fatal("failed save changed the in-memory draft or templates")
	}
	after, err := os.ReadFile(originalPath)
	if err != nil || string(after) != string(originalBytes) {
		t.Fatal("failed save changed the previous state file", err)
	}
	s.path = originalPath
	if err := s.ApplySubDesign(subdesign.Design{Final: "REJECT"}, map[string]string{"clash": "new-clash"}); err != nil {
		t.Fatal("retry failed", err)
	}
	if s.SubTemplate("qx") != "manual-qx" || s.SubDesign().Final != "REJECT" {
		t.Fatal("retry changed an unselected template or lost the new draft")
	}
}
