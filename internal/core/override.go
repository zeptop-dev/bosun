package core

import (
	"encoding/json"
	"fmt"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

// ApplyOverride deep-merges a JSON object into a rendered config: objects
// merge key by key, arrays and scalars replace, JSON null deletes the key.
// It lets an operator set a core option the panel does not expose without
// forking the renderer. An empty patch is a no-op.
// CheckOverride validates a raw override for the core (see spec.CheckOverride).
func CheckOverride(core string, patch json.RawMessage) error { return spec.CheckOverride(core, patch) }

// ApplyOverride merges the core's override into cfg after CheckOverride.
func ApplyOverride(core string, cfg map[string]any, patch json.RawMessage) error {
	if err := CheckOverride(core, patch); err != nil {
		return err
	}
	return applyOverride(cfg, patch)
}

func applyOverride(cfg map[string]any, patch json.RawMessage) error {
	if len(patch) == 0 {
		return nil
	}
	var over map[string]any
	if err := json.Unmarshal(patch, &over); err != nil {
		return fmt.Errorf("config override is not a JSON object: %w", err)
	}
	mergeInto(cfg, over)
	return nil
}

func mergeInto(dst, src map[string]any) {
	for k, v := range src {
		if v == nil {
			delete(dst, k)
			continue
		}
		sv, sok := v.(map[string]any)
		dv, dok := dst[k].(map[string]any)
		if sok && dok {
			mergeInto(dv, sv)
			continue
		}
		dst[k] = v
	}
}
