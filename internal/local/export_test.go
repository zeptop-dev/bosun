package local

import (
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func (s *Store) buildNodeForTest() (*spec.Node, []spec.User) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buildNode(time.Now())
}
