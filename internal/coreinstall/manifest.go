// Package coreinstall installs the public, fixed coremanifest catalog.
package coreinstall

import "github.com/zeptop-dev/bosun/pkg/coremanifest"

type Status = coremanifest.Status
type Asset = coremanifest.Asset
type Build = coremanifest.Build
type Release = coremanifest.Release

const (
	StatusTested  = coremanifest.StatusTested
	StatusCaution = coremanifest.StatusCaution
	StatusBroken  = coremanifest.StatusBroken
	RegistryBase  = coremanifest.RegistryBase
)

var (
	Manifest = coremanifest.Manifest
	Binary   = coremanifest.Binary
	Cores    = coremanifest.Cores
	Releases = coremanifest.Releases
	Find     = coremanifest.Find
	Resolve  = coremanifest.Resolve
	Tested   = coremanifest.Tested
	Default  = coremanifest.Default
)
