package spec

import (
	"fmt"
	"regexp"
)

const CoreManagementKind = "core_manage"
const CoreManagementTTL = 900 // downloads may take several minutes

type CorePackage struct {
	Distribution string `json:"distribution"`
	Family       string `json:"family"`
	Version      string `json:"version"`
	Status       string `json:"status"`
	Note         string `json:"note,omitempty"`
	Installed    bool   `json:"installed"`
	Available    bool   `json:"available"`
}

type CoreInstance struct {
	PreparationError string `json:"preparation_error,omitempty"`
	Distribution     string `json:"distribution"`
	Version          string `json:"version"`
	External         bool   `json:"external,omitempty"` // config.yaml pins an administrator-provided binary
}

type CoreInventory struct {
	Revision  uint64         `json:"revision"`
	Packages  []CorePackage  `json:"packages"`
	Instances []CoreInstance `json:"instances"`
}

type CoreRequest struct {
	Action       string `json:"action"` // download, activate
	Distribution string `json:"distribution"`
	Version      string `json:"version"`
	Revision     uint64 `json:"revision"` // compare-and-swap; downloads do not advance it
}

type CoreJobParams struct {
	CoreRequest
	ExpiresAt int64 `json:"expires_at"`
}

var coreVersionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_-]{0,79}$`)

func (r CoreRequest) Validate() error {
	if r.Action != "download" && r.Action != "activate" {
		return fmt.Errorf("core action must be download or activate")
	}
	switch r.Distribution {
	case "singbox", "singbox-extended", "xray", "mita", "hysteria", "snell":
	default:
		return fmt.Errorf("unknown core distribution")
	}
	if !coreVersionPattern.MatchString(r.Version) {
		return fmt.Errorf("a catalog core version is required")
	}
	return nil
}
