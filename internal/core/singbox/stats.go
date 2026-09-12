package singbox

import (
	"context"

	"google.golang.org/grpc"

	"github.com/zeptop-dev/bosun/internal/core/v2stats"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

// sing-box registers its stats service under the original V2Ray name for
// compatibility (see experimental/v2rayapi/stats.go), so that is the name on
// the wire, not the proto's experimental.v2rayapi package.
const queryStatsMethod = "/v2ray.core.app.stats.command.StatsService/QueryStats"

// queryUserStats returns per-user traffic keyed by user name. With reset the
// counters are zeroed server-side after being read. sing-box ignores the
// pattern field unless patterns are set, so all counters come back and
// v2stats keeps the user ones.
func queryUserStats(ctx context.Context, conn *grpc.ClientConn, reset bool) (map[string]spec.Traffic, error) {
	return v2stats.QueryUsers(ctx, conn, queryStatsMethod, "", reset)
}
