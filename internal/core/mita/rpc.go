package mita

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protowire"

	"github.com/zeptop-dev/bosun/internal/core/grpcraw"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

// mita's control plane is mieru.appctl.ServerManagementService over a unix
// socket. Requests used here are google.protobuf.Empty (zero bytes).
const (
	svc            = "/mieru.appctl.ServerManagementService/"
	methodStatus   = svc + "GetStatus"
	methodStart    = svc + "Start"
	methodStop     = svc + "Stop"
	methodReload   = svc + "Reload"
	methodGetUsers = svc + "GetUsers"
)

// appStatus mirrors enum mieru.appctl.AppStatus.
type appStatus int32

const (
	statusUnknown  appStatus = 0
	statusIdle     appStatus = 1
	statusStarting appStatus = 2
	statusRunning  appStatus = 3
	statusStopping appStatus = 4
	statusStopped  appStatus = 5
)

func (s appStatus) String() string {
	switch s {
	case statusIdle:
		return "IDLE"
	case statusStarting:
		return "STARTING"
	case statusRunning:
		return "RUNNING"
	case statusStopping:
		return "STOPPING"
	case statusStopped:
		return "STOPPED"
	}
	return "UNKNOWN"
}

func rpcStatus(ctx context.Context, conn *grpc.ClientConn) (appStatus, error) {
	resp, err := grpcraw.Invoke(ctx, conn, methodStatus, nil)
	if err != nil {
		return statusUnknown, err
	}
	// AppStatusMsg { status = 1 }
	b := resp
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return statusUnknown, protowire.ParseError(n)
		}
		b = b[n:]
		if num == 1 && typ == protowire.VarintType {
			v, n := protowire.ConsumeVarint(b)
			if n < 0 {
				return statusUnknown, protowire.ParseError(n)
			}
			return appStatus(v), nil
		}
		n = protowire.ConsumeFieldValue(num, typ, b)
		if n < 0 {
			return statusUnknown, protowire.ParseError(n)
		}
		b = b[n:]
	}
	return statusUnknown, nil
}

func rpcEmpty(ctx context.Context, conn *grpc.ClientConn, method string) error {
	_, err := grpcraw.Invoke(ctx, conn, method, nil)
	return err
}

// rpcUserCounters returns cumulative per-user byte counters keyed by user name.
func rpcUserCounters(ctx context.Context, conn *grpc.ClientConn) (map[string]spec.Traffic, error) {
	resp, err := grpcraw.Invoke(ctx, conn, methodGetUsers, nil)
	if err != nil {
		return nil, err
	}
	return decodeUserCounters(resp)
}

// decodeUserCounters parses
//
//	UserWithMetricsList { repeated UserWithMetrics items = 1 }
//	UserWithMetrics     { User user = 1; repeated Metric metrics = 2 }
//	User                { string name = 1; ... }
//	Metric              { string name = 1; MetricType type = 2; int64 value = 3; ... }
//
// keeping the "UploadBytes" and "DownloadBytes" counters. On the server side
// UploadBytes counts bytes received from the client, i.e. the user's upload.
func decodeUserCounters(b []byte) (map[string]spec.Traffic, error) {
	out := map[string]spec.Traffic{}
	err := eachField(b, func(num protowire.Number, typ protowire.Type, val []byte) error {
		if num != 1 || typ != protowire.BytesType {
			return nil
		}
		var name string
		var t spec.Traffic
		err := eachField(val, func(num protowire.Number, typ protowire.Type, val []byte) error {
			if typ != protowire.BytesType {
				return nil
			}
			switch num {
			case 1: // User
				return eachField(val, func(num protowire.Number, typ protowire.Type, val []byte) error {
					if num == 1 && typ == protowire.BytesType {
						name = string(val)
					}
					return nil
				})
			case 2: // Metric
				var mname string
				var mval int64
				err := eachField(val, func(num protowire.Number, typ protowire.Type, val []byte) error {
					switch {
					case num == 1 && typ == protowire.BytesType:
						mname = string(val)
					case num == 3 && typ == protowire.VarintType:
						v, _ := protowire.ConsumeVarint(val)
						mval = int64(v)
					}
					return nil
				})
				if err != nil {
					return err
				}
				switch mname {
				case "UploadBytes":
					t.Up = mval
				case "DownloadBytes":
					t.Down = mval
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
		if name != "" {
			out[name] = t
		}
		return nil
	})
	return out, err
}

// eachField walks a message and hands each field to fn. For bytes fields val
// is the payload; for varint fields val is the raw varint bytes.
func eachField(b []byte, fn func(num protowire.Number, typ protowire.Type, val []byte) error) error {
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return protowire.ParseError(n)
		}
		b = b[n:]
		var val []byte
		switch typ {
		case protowire.BytesType:
			v, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return protowire.ParseError(n)
			}
			val, b = v, b[n:]
		case protowire.VarintType:
			_, n := protowire.ConsumeVarint(b)
			if n < 0 {
				return protowire.ParseError(n)
			}
			val, b = b[:n], b[n:]
		default:
			n := protowire.ConsumeFieldValue(num, typ, b)
			if n < 0 {
				return protowire.ParseError(n)
			}
			val, b = b[:n], b[n:]
		}
		if err := fn(num, typ, val); err != nil {
			return fmt.Errorf("field %d: %w", num, err)
		}
	}
	return nil
}
