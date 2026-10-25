package subdesign

import _ "embed"

//go:embed qx_rule_parser.js
var quantumultXRuleParser string

// QuantumultXRuleParser is a self-contained resource parser for the classical
// ACL4SSR lists used by the designer. Serve it as application/javascript. It
// performs no network requests and rejects an entire update on unknown rules.
func QuantumultXRuleParser() string { return quantumultXRuleParser }
