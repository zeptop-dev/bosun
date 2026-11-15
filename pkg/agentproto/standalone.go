package agentproto

// This request capability fences a downgraded agent's first pull, even while
// the panel still holds the previous process's capability report.
const StandaloneAuthHeader = "X-Bosun-Standalone-Auth"
const StandaloneAuthVersion = "1"
