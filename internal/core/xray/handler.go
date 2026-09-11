package xray

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protowire"

	"gitlab.com/boyang-hu/bosun/internal/core/grpcraw"
	"gitlab.com/boyang-hu/bosun/pkg/spec"
)

// Xray's HandlerService lets users be added to and removed from a running
// inbound. Requests are hand-encoded:
//
//	AlterInboundRequest { tag = 1; TypedMessage operation = 2 }
//	TypedMessage        { type = 1; value = 2 }
//	AddUserOperation    { User user = 1 }
//	User                { level = 1; email = 2; TypedMessage account = 3 }
//	RemoveUserOperation { email = 1 }
const (
	methodAlterInbound = "/xray.app.proxyman.command.HandlerService/AlterInbound"
	methodQueryStats   = "/xray.app.stats.command.StatsService/QueryStats"

	typeAddUser    = "xray.app.proxyman.command.AddUserOperation"
	typeRemoveUser = "xray.app.proxyman.command.RemoveUserOperation"
)

// hotProtocols are the inbound protocols whose account message we can build.
var hotProtocols = map[spec.Protocol]bool{spec.VLESS: true, spec.VMess: true, spec.Trojan: true}

func typed(typeName string, value []byte) []byte {
	var b []byte
	b = protowire.AppendTag(b, 1, protowire.BytesType)
	b = protowire.AppendString(b, typeName)
	b = protowire.AppendTag(b, 2, protowire.BytesType)
	b = protowire.AppendBytes(b, value)
	return b
}

func strField(num protowire.Number, s string) []byte {
	b := protowire.AppendTag(nil, num, protowire.BytesType)
	return protowire.AppendString(b, s)
}

func bytesField(num protowire.Number, v []byte) []byte {
	b := protowire.AppendTag(nil, num, protowire.BytesType)
	return protowire.AppendBytes(b, v)
}

// account builds the protocol-specific account TypedMessage for u.
func account(proto spec.Protocol, u spec.User, flow string) ([]byte, error) {
	switch proto {
	case spec.VLESS:
		// xray.proxy.vless.Account { id = 1; flow = 2; encryption = 3 }
		v := strField(1, u.UUID)
		if flow != "" {
			v = append(v, strField(2, flow)...)
		}
		return typed("xray.proxy.vless.Account", v), nil
	case spec.VMess:
		// xray.proxy.vmess.Account { id = 1 }
		return typed("xray.proxy.vmess.Account", strField(1, u.UUID)), nil
	case spec.Trojan:
		// xray.proxy.trojan.Account { password = 1 }
		return typed("xray.proxy.trojan.Account", strField(1, u.Password)), nil
	}
	return nil, fmt.Errorf("xray: no hot account encoding for %s", proto)
}

func alterInbound(ctx context.Context, conn *grpc.ClientConn, tag string, op []byte) error {
	req := strField(1, tag)
	req = append(req, bytesField(2, op)...)
	_, err := grpcraw.Invoke(ctx, conn, methodAlterInbound, req)
	return err
}

func addUser(ctx context.Context, conn *grpc.ClientConn, tag string, proto spec.Protocol, u spec.User, flow string) error {
	acc, err := account(proto, u, flow)
	if err != nil {
		return err
	}
	user := strField(2, u.Name)
	user = append(user, bytesField(3, acc)...)
	op := typed(typeAddUser, bytesField(1, user))
	return alterInbound(ctx, conn, tag, op)
}

func removeUser(ctx context.Context, conn *grpc.ClientConn, tag string, email string) error {
	op := typed(typeRemoveUser, strField(1, email))
	return alterInbound(ctx, conn, tag, op)
}
