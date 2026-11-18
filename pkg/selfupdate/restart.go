package selfupdate

import (
	"log/slog"
	"os"
	"sync"
	"syscall"
	"time"
)

var restartOnce sync.Once

// Restart requests normal process shutdown after delay so the service manager
// can start the new binary. Callers must install a SIGTERM handler (as both
// service entry points do) and allow time for the initiating response to flush.
// The handler must wait for cleanup before returning from main: os.Exit here
// would bypass traffic checkpoints and leave proxy children alive under OpenRC.
// Repeated requests share the first deadline and cannot interrupt cleanup.
func Restart(delay time.Duration) {
	restartOnce.Do(func() {
		time.AfterFunc(delay, func() {
			p, err := os.FindProcess(os.Getpid())
			if err == nil {
				err = p.Signal(syscall.SIGTERM)
			}
			if err != nil {
				// Do not fall back to an abrupt exit and orphan running cores.
				slog.Error("could not request graceful restart", "err", err)
			}
		})
	})
}
