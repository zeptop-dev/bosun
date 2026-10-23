package sysinfo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/disk"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

const (
	filesystemInterval          = 15 * time.Second
	filesystemDiscoveryInterval = time.Minute
	filesystemTimeout           = 3 * time.Second
	filesystemMaxAge            = 90 * time.Second
	maxFilesystems              = 256
	filesystemWorkers           = 3 // data volumes; a separate slot is reserved for /
)

type filesystemMount struct {
	resource spec.FilesystemResource
	identity string // includes mount instance; late reads cannot follow a remount
}

type filesystemRead struct {
	usage   *disk.UsageStat
	members []string
}

type filesystemEntry struct {
	mount     filesystemMount
	value     spec.FilesystemResource
	attempted time.Time
	running   bool
}

// statfs and FUSE xattr calls can remain stuck in the kernel after cancellation.
// A slot stays occupied until the real call exits. Heartbeats only copy cached
// values and never wait for these workers; remounts cannot accumulate new calls.
type filesystemSampler struct {
	mu               sync.Mutex
	entries          map[string]*filesystemEntry
	discovered       time.Time
	discoveryAttempt time.Time
	discovering      bool
	rootRunning      bool
	running          int
	discover         func(context.Context) ([]filesystemMount, error)
	read             func(context.Context, filesystemMount, []filesystemMount) (filesystemRead, error)
}

func (p *filesystemSampler) snapshot(now time.Time) []spec.FilesystemResource {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.discovering && (p.discoveryAttempt.IsZero() || now.Sub(p.discoveryAttempt) >= filesystemDiscoveryInterval) {
		p.discovering, p.discoveryAttempt = true, now
		discover := p.discover
		if discover == nil {
			discover = discoverFilesystems
		}
		go p.refresh(discover)
	}
	if p.entries == nil {
		return nil
	}
	entries := make([]*filesystemEntry, 0, len(p.entries))
	mounts := make([]filesystemMount, 0, len(p.entries))
	for _, entry := range p.entries {
		entries = append(entries, entry)
		mounts = append(mounts, entry.mount)
	}
	// Fair scheduling: completed fast volumes cannot starve mounts beyond the
	// worker limit. Root has its own slot and is never queued behind a data pool.
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].attempted.Equal(entries[j].attempted) {
			return entries[i].mount.resource.Mount < entries[j].mount.resource.Mount
		}
		return entries[i].attempted.Before(entries[j].attempted)
	})
	out := make([]spec.FilesystemResource, 0, len(entries))
	for _, entry := range entries {
		root := entry.mount.resource.Mount == "/"
		available := (!root && p.running < filesystemWorkers) || (root && !p.rootRunning)
		if available && !entry.running && now.Sub(p.discovered) <= filesystemMaxAge && (entry.attempted.IsZero() || now.Sub(entry.attempted) >= filesystemInterval) {
			entry.running, entry.attempted = true, now
			if root {
				p.rootRunning = true
			} else {
				p.running++
			}
			read := p.read
			if read == nil {
				read = readFilesystem
			}
			go p.sample(entry, mounts, read)
		}
		value := entry.value
		if value.SampledAt == 0 || now.Sub(time.UnixMilli(value.SampledAt)) > filesystemMaxAge || (entry.running && now.Sub(entry.attempted) >= filesystemTimeout) {
			clearFilesystemUsage(&value)
		}
		// The resource itself and its pointed-to counters are immutable. Only
		// the membership slice requires a copy for callers to own their result.
		value.MemberMounts = append([]string(nil), value.MemberMounts...)
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Mount < out[j].Mount })
	return out
}

func (p *filesystemSampler) refresh(discover func(context.Context) ([]filesystemMount, error)) {
	ctx, cancel := context.WithTimeout(context.Background(), filesystemTimeout)
	defer cancel()
	mounts, err := discover(ctx)
	p.mu.Lock()
	p.discovering = false
	if err != nil || ctx.Err() != nil {
		p.mu.Unlock()
		return
	}
	next := make(map[string]*filesystemEntry, len(mounts))
	for _, mount := range mounts {
		if len(next) >= maxFilesystems {
			break
		}
		old := p.entries[mount.resource.Mount]
		if old != nil && old.mount.identity == mount.identity {
			next[mount.resource.Mount] = old
		} else {
			next[mount.resource.Mount] = &filesystemEntry{mount: mount, value: mount.resource}
		}
	}
	p.entries, p.discovered = next, time.Now()
	p.mu.Unlock()
	// Start the first readings promptly, without waiting for the next beat.
	p.snapshot(time.Now())
}

func (p *filesystemSampler) sample(entry *filesystemEntry, mounts []filesystemMount, read func(context.Context, filesystemMount, []filesystemMount) (filesystemRead, error)) {
	ctx, cancel := context.WithTimeout(context.Background(), filesystemTimeout)
	defer cancel()
	result, err := read(ctx, entry.mount, mounts)
	p.mu.Lock()
	defer func() {
		p.mu.Unlock()
		// Drain newly discovered volumes without waiting another heartbeat
		// per batch. Per-volume retry times still bound every subsequent read.
		p.snapshot(time.Now())
	}()
	entry.running = false
	if entry.mount.resource.Mount == "/" {
		p.rootRunning = false
	} else {
		p.running--
	}
	if p.entries[entry.mount.resource.Mount] != entry {
		return
	}
	value := entry.mount.resource
	// Failed/late readings never turn into a new successful timestamp.
	value.SampledAt = entry.value.SampledAt
	if err == nil && ctx.Err() == nil && result.usage != nil && result.usage.Total > 0 && result.usage.Used <= result.usage.Total {
		usage := result.usage
		value.Total, value.Used = &usage.Total, &usage.Used
		if usage.InodesTotal > 0 && usage.InodesUsed <= usage.InodesTotal {
			value.InodesTotal, value.InodesUsed = &usage.InodesTotal, &usage.InodesUsed
		}
		value.MemberMounts = append([]string(nil), result.members...)
		value.SampledAt = time.Now().UnixMilli()
	}
	entry.value = value
}

func clearFilesystemUsage(value *spec.FilesystemResource) {
	value.Total, value.Used, value.InodesTotal, value.InodesUsed = nil, nil, nil, nil
	value.MemberMounts = nil
}

func filesystemID(mount, source, fs, root string) string {
	sum := sha256.Sum256([]byte(fs + "\x00" + source + "\x00" + root + "\x00" + mount))
	return hex.EncodeToString(sum[:16])
}

func remoteFS(fs string) bool {
	if fs == "fuse.mergerfs" {
		return false
	}
	return strings.HasPrefix(fs, "nfs") || strings.HasPrefix(fs, "fuse") || fs == "cifs" || fs == "smbfs" || fs == "autofs" || fs == "ceph" || fs == "9p" || fs == "afs" || fs == "coda" || fs == "glusterfs"
}

func pseudoFS(fs string) bool {
	switch fs {
	case "proc", "sysfs", "tmpfs", "devtmpfs", "devpts", "cgroup", "cgroup2", "pstore", "securityfs", "debugfs", "tracefs", "configfs", "fusectl", "mqueue", "hugetlbfs", "rpc_pipefs", "binfmt_misc", "nsfs", "efivarfs", "bpf", "overlay", "aufs", "squashfs", "ramfs", "rootfs":
		return true
	}
	return false
}

var errFilesystemChanged = errors.New("filesystem mount changed during sampling")

func readVerifiedFilesystem(ctx context.Context, expected filesystemMount, discover func(context.Context) ([]filesystemMount, error), usage func(context.Context, string) (*disk.UsageStat, error), branches func(string) (string, error)) (filesystemRead, error) {
	before, err := discover(ctx)
	if err != nil || !containsFilesystem(before, expected) {
		return filesystemRead{}, errFilesystemChanged
	}
	value, err := usage(ctx, expected.resource.Mount)
	if err != nil {
		return filesystemRead{}, err
	}
	result := filesystemRead{usage: value}
	if expected.resource.Pool && branches != nil && ctx.Err() == nil {
		if value, err := branches(expected.resource.Mount); err == nil {
			result.members = mergerfsMemberMounts(value, expected.resource.Mount, before)
		}
	}
	after, err := discover(ctx)
	if err != nil || !containsFilesystem(after, expected) {
		return filesystemRead{}, errFilesystemChanged
	}
	// Membership cannot be established against an already-unmounted branch.
	for _, member := range result.members {
		for _, mount := range before {
			if mount.resource.Mount == member && !containsFilesystem(after, mount) {
				result.members = nil
				break
			}
		}
	}
	return result, nil
}

func containsFilesystem(mounts []filesystemMount, expected filesystemMount) bool {
	for _, mount := range mounts {
		if mount.resource.Mount == expected.resource.Mount {
			return mount.identity == expected.identity
		}
	}
	return false
}

// Only exact mount points from the current inventory establish membership.
// Configured subdirectories, unsupported syntax or missing mounts remain
// unknown; equal capacities and fsname strings never establish a relationship.
func mergerfsMemberMounts(value string, pool string, mounts []filesystemMount) []string {
	if value == "" || len(value) > 64<<10 {
		return nil
	}
	known := map[string]bool{}
	for _, mount := range mounts {
		known[mount.resource.Mount] = true
	}
	parts := strings.Split(value, ":")
	if len(parts) > maxFilesystems {
		return nil
	}
	members := make([]string, 0, len(parts))
	seen := map[string]bool{}
	for _, branch := range parts {
		if !known[branch] {
			if idx := strings.LastIndexByte(branch, '='); idx > 0 {
				options := strings.Split(branch[idx+1:], ",")
				if options[0] == "RW" || options[0] == "RO" || options[0] == "NC" {
					branch = branch[:idx]
				}
			}
		}
		if branch == pool || branch == "/" || !known[branch] {
			return nil
		}
		if !seen[branch] {
			members = append(members, branch)
			seen[branch] = true
		}
	}
	sort.Strings(members)
	return members
}
