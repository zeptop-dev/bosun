//go:build linux

package sysinfo

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/shirou/gopsutil/v4/disk"
	"golang.org/x/sys/unix"
)

func discoverFilesystems(ctx context.Context) ([]filesystemMount, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	const limit = 8 << 20
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > limit {
		return nil, fmt.Errorf("mount inventory too large")
	}
	return parseFilesystemMountinfo(bytes.NewReader(raw))
}

func readFilesystem(ctx context.Context, mount filesystemMount, _ []filesystemMount) (filesystemRead, error) {
	return readVerifiedFilesystem(ctx, mount, discoverFilesystems, disk.UsageWithContext, func(mountpoint string) (string, error) {
		// This pseudo-file is the documented read-only runtime config API.
		// Fixed-size reads avoid unbounded allocation and do not execute a tool.
		buf := make([]byte, 64<<10)
		n, err := unix.Getxattr(filepath.Join(mountpoint, ".mergerfs"), "user.mergerfs.branches", buf)
		if err != nil {
			return "", err
		}
		return string(buf[:n]), nil
	})
}
