package agentproto

import "time"

const (
	ConfigSessionHeader  = "X-Bosun-Config-Session"
	ConfigDeliveryHeader = "X-Bosun-Config-Delivery"
)

// ConfigDelivery binds configuration observation to one agent process session
// and complete state delivery. It is metadata, not part of the state revision.
// A dynamic user/job change needs a new delivery even with the same structural
// ConfigRevision. An unchanged ETag alone cannot acknowledge a new session.
type ConfigDelivery struct {
	ID      string `json:"id"`
	Session string `json:"session"`
}

// ConfigReceipt records observation of a particular complete state delivery.
// Applied requires the current process to complete both apply paths. It does
// not prove liveness, end-to-end connectivity or matching credential material
// from ConfigRevision alone; consumers must also check StateRevision.
type ConfigReceipt struct {
	DeliveryID     string    `json:"delivery_id"`
	Session        string    `json:"session"`
	ConfigRevision string    `json:"config_revision"`
	StateRevision  string    `json:"state_revision"`
	Sequence       uint64    `json:"sequence"`
	ObservedAt     time.Time `json:"observed_at"`
	Applied        bool      `json:"applied"`
}
