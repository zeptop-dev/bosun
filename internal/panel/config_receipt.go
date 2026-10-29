package panel

// ConfigState is the provenance of a state accessor's last consumed value.
// ConfigRevision alone excludes dynamic permissions and is never sufficient
// to confirm that the complete delivered state was successfully applied.
type ConfigState struct {
	Session, DeliveryID, ConfigRevision, StateRevision string
	Online                                             bool
}

func (s ConfigState) Valid() bool {
	return s.Online && s.Session != "" && s.DeliveryID != "" && s.ConfigRevision != "" && s.StateRevision != ""
}

// SameDelivery excludes connectivity, which can change without changing state.
func (s ConfigState) SameDelivery(other ConfigState) bool {
	s.Online, other.Online = false, false
	return s == other
}

// ConsumedConfigSource cannot borrow an asynchronous watcher's latest state.
// nodeUsers is empty when those accessors consumed different delivery tuples.
type ConsumedConfigSource interface {
	ConsumedConfig() (session string, nodeUsers, forwards ConfigState)
}
