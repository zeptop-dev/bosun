package agentproto

import (
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"time"
)

// RenderedConfigReport is optional evidence accompanying this report's exact
// ConfigReceipt (delivery, session, complete state, observation and sequence).
// It is never a desired-model hash or a dump of the core's current memory.
// Receivers must validate both objects and bind them to an accepted receipt;
// malformed or absent evidence must not reject otherwise valid accounting.
type RenderedConfigReport struct {
	Version   int                `json:"version"`
	Status    string             `json:"status"` // observed, unavailable
	Artifacts []RenderedArtifact `json:"artifacts"`
}

// RenderedArtifact describes files successfully activated by one core adapter.
// Activation files exclude subsequent runtime user/API/auth updates, external
// certificate contents, host rules and network reachability. RuntimeUpdates
// explicitly identifies later accepted changes outside those activation files.
// Digest is HMAC-SHA256 with an in-memory random secret, not a guessable raw file
// hash. It is comparable only within the reporting bosun process; a restart or
// adapter replacement can change it without a configuration change.
type RenderedArtifact struct {
	Core           string    `json:"core"`
	Digest         string    `json:"digest"`
	DigestScope    string    `json:"digest_scope"` // process
	Scope          string    `json:"scope"`        // activation_files
	Format         string    `json:"format"`       // json, yaml, ini
	Files          int       `json:"files"`
	Processes      int       `json:"processes"`
	ActivatedAt    time.Time `json:"activated_at"` // earliest included activation
	RuntimeUpdates bool      `json:"runtime_updates"`
}

const MaxRenderedConfigBytes = 4 << 10

var renderedDigest = regexp.MustCompile(`^rcf1-[0-9a-f]{64}$`)

func (r *RenderedConfigReport) UnmarshalJSON(raw []byte) error {
	*r = RenderedConfigReport{Version: -1}
	if len(raw) > MaxRenderedConfigBytes {
		return nil
	}
	type wire RenderedConfigReport
	var v wire
	if json.Unmarshal(raw, &v) == nil {
		*r = RenderedConfigReport(v)
	}
	return nil
}

// ValidateRenderedConfigReport validates only the bounded privacy allowlist.
// A receiver must separately require a matching fresh accepted ConfigReceipt;
// Status=observed additionally requires receipt.Applied. Empty observed sets
// mean a successful configuration with no active proxy cores, never legacy or
// missing evidence. Unknown JSON keys are discarded by typed decoding.
func ValidateRenderedConfigReport(r *RenderedConfigReport) error {
	bad := errors.New("invalid rendered configuration evidence")
	if r == nil || r.Version != 1 || !slices.Contains([]string{"observed", "unavailable"}, r.Status) || len(r.Artifacts) > 6 {
		return bad
	}
	seen := map[string]bool{}
	for _, a := range r.Artifacts {
		if !slices.Contains([]string{"singbox", "singbox-extended", "xray", "hysteria", "mita", "snell"}, a.Core) || seen[a.Core] || !renderedDigest.MatchString(a.Digest) || a.DigestScope != "process" || a.Scope != "activation_files" || a.Files < 1 || a.Files > 16384 || a.Processes < 1 || a.Processes > 16384 || !sampleTime(a.ActivatedAt) {
			return bad
		}
		format := "json"
		if a.Core == "hysteria" {
			format = "yaml"
		} else if a.Core == "snell" {
			format = "ini"
		}
		if a.Format != format {
			return bad
		}
		seen[a.Core] = true
	}
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > MaxRenderedConfigBytes {
		return bad
	}
	return nil
}
