package core

import (
	"encoding/json"
	"fmt"
)

// ApplyOverride deep-merges a JSON object into a rendered config: objects
// merge key by key, arrays and scalars replace, JSON null deletes the key.
// It lets an operator set a core option the panel does not expose without
// forking the renderer. An empty patch is a no-op.
func ApplyOverride(cfg map[string]any, patch json.RawMessage) error {
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
