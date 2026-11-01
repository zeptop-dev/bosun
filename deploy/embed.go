// Package deploy embeds the native service definitions.
package deploy

import _ "embed"

//go:embed bosun.service
var Service string

//go:embed bosun.initd
var Initd string
