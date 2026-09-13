package sharelink

import "github.com/zeptop-dev/bosun/pkg/spec"

// Line is one server as a client sees it: the protocol settings in Inbound
// form plus the address and the user's identity.
type Line struct {
	Name     string
	Host     string
	Port     int
	Inbound  spec.Inbound
	UUID     string
	Password string
}
