//go:build !linux

package sysinfo

import (
	"context"
	"sort"

	"github.com/shirou/gopsutil/v4/disk"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

func discoverFilesystems(ctx context.Context) ([]filesystemMount, error) {
	parts, err := disk.PartitionsWithContext(ctx, false)
	if err != nil {
		return nil, err
	}
	// Some platforms omit the container root from physical partitions.
	parts = append(parts, disk.PartitionStat{Mountpoint: "/"})
	seen := map[string]bool{}
	out := make([]filesystemMount, 0, min(len(parts), maxFilesystems))
	for _, part := range parts {
		if seen[part.Mountpoint] || (part.Mountpoint != "/" && (remoteFS(part.Fstype) || pseudoFS(part.Fstype))) {
			continue
		}
		seen[part.Mountpoint] = true
		id := filesystemID(part.Mountpoint, part.Device, part.Fstype, "")
		out = append(out, filesystemMount{resource: spec.FilesystemResource{Mount: part.Mountpoint, Device: part.Device, Type: part.Fstype, ID: id}, identity: id})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].resource.Mount < out[j].resource.Mount })
	if len(out) > maxFilesystems {
		out = out[:maxFilesystems]
	}
	return out, nil
}

func readFilesystem(ctx context.Context, mount filesystemMount, _ []filesystemMount) (filesystemRead, error) {
	usage, err := disk.UsageWithContext(ctx, mount.resource.Mount)
	return filesystemRead{usage: usage}, err
}
