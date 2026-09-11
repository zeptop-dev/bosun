// Package grpcraw invokes gRPC methods with hand-encoded protobuf payloads.
// Core control planes expose a handful of tiny messages; encoding them with
// protowire avoids generated stubs and any dependency on the cores' modules.
package grpcraw

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Codec passes pre-encoded bytes straight through gRPC.
type Codec struct{}

func (Codec) Marshal(v any) ([]byte, error) {
	b, ok := v.([]byte)
	if !ok {
		return nil, fmt.Errorf("grpcraw: expected []byte, got %T", v)
	}
	return b, nil
}

func (Codec) Unmarshal(data []byte, v any) error {
	p, ok := v.(*[]byte)
	if !ok {
		return fmt.Errorf("grpcraw: expected *[]byte, got %T", v)
	}
	*p = append((*p)[:0], data...)
	return nil
}

func (Codec) Name() string { return "raw" }

// Dial opens an insecure connection. target follows gRPC naming, e.g.
// "127.0.0.1:9101" or "unix:///run/mita.sock".
func Dial(target string) (*grpc.ClientConn, error) {
	return grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
}

// Invoke calls a unary method with a raw request and returns the raw response.
func Invoke(ctx context.Context, conn *grpc.ClientConn, method string, req []byte) ([]byte, error) {
	var resp []byte
	if err := conn.Invoke(ctx, method, req, &resp, grpc.ForceCodec(Codec{})); err != nil {
		return nil, err
	}
	return resp, nil
}
