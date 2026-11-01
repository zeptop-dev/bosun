// Package scripts embeds the installer used by Captain bootstrap delivery.
package scripts

import _ "embed"

//go:embed install.sh
var Install string
