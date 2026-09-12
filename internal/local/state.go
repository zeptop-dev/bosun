// Package local is bosun's standalone mode: inbounds, users and forwards
// live in a JSON state file on the node and the built-in web UI edits them.
// The same package implements panel.Driver over that file, so the agent does
// not care whether its desired state comes from Captain or from here.
//
// Modes: in "local" mode the file is authoritative. Adopting a Captain
// panel snapshots the local objects, switches the mode to "managed" and the
// agent restarts on the Captain driver; detaching restores the snapshot (or
// keeps the last managed state as the new local config).
package local

import (
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

// Mode is who owns the node's desired state.
type Mode string

const (
	ModeLocal   Mode = "local"
	ModeManaged Mode = "managed"
)

// State is the whole standalone configuration, persisted as one JSON file.
type State struct {
	Revision int64 `json:"revision"`

	Admin Admin `json:"admin"`
	Mode  Mode  `json:"mode"`
	// Managed is set while a panel owns the node.
	Managed *Managed `json:"managed,omitempty"`
	// Snapshot is the local config saved when a panel took over.
	Snapshot *Snapshot `json:"snapshot,omitempty"`

	Settings Settings `json:"settings"`

	Inbounds []Inbound      `json:"inbounds"`
	Users    []User         `json:"users"`
	Forwards []spec.Forward `json:"forwards"`
}

// Admin is the single local login.
type Admin struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
}

// Managed records the adopting panel.
type Managed struct {
	URL      string    `json:"url"`
	PairedAt time.Time `json:"paired_at"`
}

// Snapshot is the local objects before a takeover.
type Snapshot struct {
	TakenAt  time.Time      `json:"taken_at"`
	Inbounds []Inbound      `json:"inbounds"`
	Users    []User         `json:"users"`
	Forwards []spec.Forward `json:"forwards"`
}

// Settings are node-wide values the UI edits.
type Settings struct {
	// PublicHost is the address clients connect to; used in share links. When
	// empty the web UI falls back to the host it was reached on.
	PublicHost string `json:"public_host"`
	// NodeName prefixes share-link names.
	NodeName string `json:"node_name"`
}

// Inbound is a spec.Inbound plus local bookkeeping.
type Inbound struct {
	spec.Inbound
	Remark  string `json:"remark,omitempty"`
	Enabled bool   `json:"enabled"`
	// DisplayHost/DisplayPort override the address shown in share links, for
	// entrances that forward to this node (an IPLC provider's front door).
	DisplayHost string `json:"display_host,omitempty"`
	DisplayPort int    `json:"display_port,omitempty"`
}

// User is a local subscriber with its own accounting.
type User struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	UUID     string `json:"uuid"`
	Password string `json:"password"`
	SubToken string `json:"sub_token"`
	Enabled  bool   `json:"enabled"`

	QuotaBytes int64      `json:"quota_bytes"` // 0 = unlimited
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	Up         int64      `json:"up"`
	Down       int64      `json:"down"`
	CreatedAt  time.Time  `json:"created_at"`
	// InboundTags restricts the user to these inbounds; empty = all.
	InboundTags []string `json:"inbound_tags,omitempty"`
}

// Usable reports whether the user should be provisioned right now.
func (u User) Usable(now time.Time) bool {
	if !u.Enabled {
		return false
	}
	if u.ExpiresAt != nil && now.After(*u.ExpiresAt) {
		return false
	}
	if u.QuotaBytes > 0 && u.Up+u.Down >= u.QuotaBytes {
		return false
	}
	return true
}

// Spec converts to the agent's user model. Name is the stats key.
func (u User) Spec() spec.User {
	pw := u.Password
	if pw == "" {
		pw = u.UUID
	}
	return spec.User{ID: u.ID, Name: u.UUID, UUID: u.UUID, Password: pw}
}
