package sysinfo

import (
	"bufio"
	"fmt"
	"io"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

type mountinfoEntry struct {
	mount         filesystemMount
	device        string
	root          string
	subvolume     string
	subvolumeRoot string
	number        int
	parent        int
}

// Parse the calling process's namespace rather than /proc/1: a path is only
// safe to stat when the observed mount exists in the collector's namespace.
func parseFilesystemMountinfo(reader io.Reader) ([]filesystemMount, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	byPath := map[string][]mountinfoEntry{}
	byID := map[int]mountinfoEntry{}
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), " - ", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid mountinfo separator")
		}
		left, right := strings.Fields(parts[0]), strings.Fields(parts[1])
		if len(left) < 6 || len(right) < 3 {
			return nil, fmt.Errorf("invalid mountinfo fields")
		}
		number, err := strconv.Atoi(left[0])
		if err != nil || number < 1 {
			return nil, fmt.Errorf("invalid mountinfo identity")
		}
		parent, err := strconv.Atoi(left[1])
		if err != nil || parent < 1 {
			return nil, fmt.Errorf("invalid mountinfo parent")
		}
		root, err := unescapeMountinfo(left[3])
		if err != nil {
			return nil, err
		}
		mount, err := unescapeMountinfo(left[4])
		if err != nil {
			return nil, err
		}
		source, err := unescapeMountinfo(right[1])
		if err != nil {
			return nil, err
		}
		if !strings.HasPrefix(mount, "/") || path.Clean(mount) != mount {
			return nil, fmt.Errorf("invalid mount point")
		}
		fs := right[0]
		resource := spec.FilesystemResource{Mount: mount, Device: source, Type: fs, Pool: fs == "fuse.mergerfs", ID: filesystemID(mount, source, fs, root)}
		entry := mountinfoEntry{mount: filesystemMount{resource: resource, identity: left[0] + ":" + left[2] + ":" + resource.ID}, root: root, device: left[2], number: number, parent: parent}
		if fs == "btrfs" {
			for _, opt := range strings.Split(right[2], ",") {
				if strings.HasPrefix(opt, "subvolid=") {
					entry.subvolume = opt
				}
				if value, ok := strings.CutPrefix(opt, "subvol="); ok {
					entry.subvolumeRoot, err = unescapeMountinfo(value)
					if err != nil {
						return nil, err
					}
				}
			}
		}
		if _, exists := byID[number]; exists {
			return nil, fmt.Errorf("duplicate mountinfo identity")
		}
		byID[number] = entry
		byPath[mount] = append(byPath[mount], entry)
		if len(byID) > 8192 {
			return nil, fmt.Errorf("mount inventory too large")
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	// Stacked mounts form a parent chain, independent of record order. Retain
	// unsupported overmounts here too, otherwise a hidden local mount might
	// cause a statfs call against a remote filesystem at the same pathname.
	visible := map[string]mountinfoEntry{}
	for mount, candidates := range byPath {
		parents := map[int]bool{}
		for _, candidate := range candidates {
			if candidate.parent != candidate.number {
				parents[candidate.parent] = true
			}
		}
		var top mountinfoEntry
		count := 0
		for _, candidate := range candidates {
			if !parents[candidate.number] {
				top = candidate
				count++
			}
		}
		if count == 1 {
			visible[mount] = top
		}
	}
	entries := make([]mountinfoEntry, 0, len(visible))
	for _, entry := range visible {
		if !visibleMountAncestors(entry, visible, byID) {
			continue
		}
		fs := entry.mount.resource
		if fs.Mount != "/" && (remoteFS(fs.Type) || pseudoFS(fs.Type)) {
			continue
		}
		// A subdirectory/file bind is not an independent storage volume. In
		// containers, /etc/hosts binds otherwise expose the host's whole disk
		// as a data volume. Preserve container roots and real Btrfs subvolumes.
		if fs.Mount != "/" && entry.root != "/" && !(fs.Type == "btrfs" && entry.root == entry.subvolumeRoot) {
			continue
		}
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		if (a.mount.resource.Mount == "/") != (b.mount.resource.Mount == "/") {
			return a.mount.resource.Mount == "/"
		}
		if (a.root == "/") != (b.root == "/") {
			return a.root == "/"
		}
		return a.number < b.number
	})
	out := make([]filesystemMount, 0, min(len(entries), maxFilesystems))
	seen := map[string]bool{}
	for _, entry := range entries {
		fs := entry.mount.resource
		key := entry.device + "\x00" + fs.Type
		if fs.Type == "zfs" {
			key += "\x00" + fs.Device
		}
		if fs.Type == "btrfs" {
			if entry.subvolume != "" {
				key += "\x00" + entry.subvolume
			} else {
				key += "\x00" + entry.root
			}
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, entry.mount)
		if len(out) >= maxFilesystems {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].resource.Mount < out[j].resource.Mount })
	return out, nil
}

func visibleMountAncestors(entry mountinfoEntry, visible map[string]mountinfoEntry, byID map[int]mountinfoEntry) bool {
	seenIDs := map[int]bool{}
	seenPaths := map[string]bool{}
	for {
		if seenIDs[entry.number] {
			return false
		}
		seenIDs[entry.number] = true
		mount := entry.mount.resource.Mount
		if !seenPaths[mount] && visible[mount].number != entry.number {
			return false
		}
		seenPaths[mount] = true
		if entry.parent == entry.number {
			return true
		}
		parent, exists := byID[entry.parent]
		if !exists {
			return true
		}
		entry = parent
	}
}

func unescapeMountinfo(value string) (string, error) {
	var out strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] != '\\' {
			out.WriteByte(value[i])
			continue
		}
		if i+3 >= len(value) {
			return "", fmt.Errorf("invalid mountinfo escape")
		}
		switch value[i+1 : i+4] {
		case "040":
			out.WriteByte(' ')
		case "011":
			out.WriteByte('\t')
		case "012":
			out.WriteByte('\n')
		case "134":
			out.WriteByte('\\')
		default:
			return "", fmt.Errorf("invalid mountinfo escape")
		}
		i += 3
	}
	return out.String(), nil
}
