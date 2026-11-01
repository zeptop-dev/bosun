// Package bootstrap exposes the installer and service definitions from this
// exact bosun module version; it never fetches a mutable upstream branch.
package bootstrap

import (
	"github.com/zeptop-dev/bosun/deploy"
	"github.com/zeptop-dev/bosun/scripts"
)

func File(name string) ([]byte, bool) {
	switch name {
	case "install.sh":
		return []byte(scripts.Install), true
	case "bosun.service":
		return []byte(deploy.Service), true
	case "bosun.initd":
		return []byte(deploy.Initd), true
	default:
		return nil, false
	}
}
