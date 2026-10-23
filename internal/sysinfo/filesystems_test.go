package sysinfo

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shirou/gopsutil/v4/disk"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

func TestFilesystemMountinfoLocalPoolsAndSharedCapacity(t *testing.T) {
	raw := `1 1 0:1 / / rw - overlay overlay rw
2 1 8:1 / /data rw shared:7 future:yes - ext4 /dev/sda1 rw
3 1 8:1 /subdir /mnt/bind rw - ext4 /dev/sda1 rw
4 1 8:2 / /mnt/other rw - xfs /dev/sdb1 rw
5 1 0:5 / /pool rw - fuse.mergerfs data rw
6 1 0:6 / /remote rw - fuse.sshfs remote rw
7 1 0:7 / /network rw - nfs4 example.com:/data rw
8 1 0:8 / /run rw - tmpfs tmpfs rw
9 1 0:9 / /proc rw - proc proc rw
10 1 0:10 /@home /home rw - btrfs /dev/sdc1 rw,subvolid=256,subvol=/@home
11 1 0:10 /@snap /snap rw - btrfs /dev/sdc1 rw,subvolid=257,subvol=/@snap
12 1 0:10 /@home/subdir /mnt/btrfs-bind rw - btrfs /dev/sdc1 rw,subvolid=256,subvol=/@home
13 1 0:11 / /zdata rw - zfs pool/data rw
14 1 0:12 / /zbackup rw - zfs pool/backup rw
15 1 253:0 / /lvm rw - ext4 /dev/mapper/vg-data rw
16 1 9:0 / /raid rw - ext4 /dev/md0 rw
17 1 0:13 / /containers rw - overlay overlay rw
18 1 8:4 / /mnt/data\040space rw - ext4 /dev/disk\134name rw
19 1 8:5 / /mnt/tab\011line\012break rw - ext4 /dev/sde1 rw
20 1 8:6 /var/lib/container/hosts /etc/hosts rw - ext4 /dev/sdf1 rw
21 1 8:6 /var/lib/container/resolv.conf /etc/resolv.conf rw - ext4 /dev/sdf1 rw
22 1 8:7 /only-subdirectory /mnt/bind-only rw - ext4 /dev/sdg1 rw
`
	mounts, err := parseFilesystemMountinfo(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]spec.FilesystemResource{}
	for _, mount := range mounts {
		got[mount.resource.Mount] = mount.resource
		if len(mount.resource.ID) != 32 || strings.Contains(mount.resource.ID, "/") {
			t.Fatalf("non-opaque ID: %q", mount.resource.ID)
		}
		if mount.resource.Total != nil || mount.resource.SampledAt != 0 {
			t.Fatal("mount inventory fabricated capacity")
		}
	}
	want := []string{"/", "/data", "/mnt/other", "/pool", "/home", "/snap", "/zdata", "/zbackup", "/lvm", "/raid", "/mnt/data space", "/mnt/tab\tline\nbreak"}
	if len(got) != len(want) {
		t.Fatalf("unexpected mounts: %+v", got)
	}
	for _, mount := range want {
		if _, ok := got[mount]; !ok {
			t.Errorf("missing %q", mount)
		}
	}
	if !got["/pool"].Pool || got["/zdata"].Pool {
		t.Fatal("pool type guessed")
	}
	if got["/mnt/data space"].Device != "/dev/disk\\name" {
		t.Fatal("mount escaping lost")
	}
	// Reboots may renumber mount IDs; the public-opaque stable identifier does
	// not contain that instance number, while the sampling identity must.
	again, _ := parseFilesystemMountinfo(strings.NewReader(strings.Replace(raw, "2 1 8:1", "32 1 8:1", 1)))
	for _, mount := range again {
		if mount.resource.Mount == "/data" && mount.resource.ID != got["/data"].ID {
			t.Fatal("ID changed with mount instance")
		}
	}
}

func TestFilesystemMountinfoContainerSubdirectoryRoot(t *testing.T) {
	mounts, err := parseFilesystemMountinfo(strings.NewReader("1 1 8:1 /containers/root / rw - ext4 /dev/sda1 rw\n"))
	if err != nil || len(mounts) != 1 || mounts[0].resource.Mount != "/" {
		t.Fatalf("container root omitted: %v %v", mounts, err)
	}
}

func TestFilesystemMountinfoOvermounts(t *testing.T) {
	// The top remote mount precedes its hidden local parent in this input.
	// Children of the hidden mount must also be excluded from path probing.
	raw := `1 1 8:0 / / rw - ext4 /dev/root rw
4 2 0:4 / /data rw - nfs4 example.com:/data rw
3 2 8:3 / /data/child rw - xfs /dev/sdc1 rw
2 1 8:2 / /data rw - ext4 /dev/sdb1 rw
5 4 8:5 / /data/visible rw - ext4 /dev/sde1 rw
`
	mounts, err := parseFilesystemMountinfo(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	got := []string{}
	for _, mount := range mounts {
		got = append(got, mount.resource.Mount)
	}
	if !reflect.DeepEqual(got, []string{"/", "/data/visible"}) {
		t.Fatalf("hidden/remote mounts leaked: %v", got)
	}
	for _, raw := range []string{"bad", "1 1 8:1 / /data\\999 rw - ext4 /dev/sda1 rw", "1 1 8:1 / relative rw - ext4 /dev/sda1 rw"} {
		if _, err := parseFilesystemMountinfo(strings.NewReader(raw)); err == nil {
			t.Fatalf("accepted malformed mountinfo: %q", raw)
		}
	}
}

func TestFilesystemFilters(t *testing.T) {
	for _, fs := range []string{"nfs", "nfs4", "cifs", "smbfs", "autofs", "fuse", "fuse.sshfs", "fuse.rclone", "fuseblk", "ceph", "9p", "afs", "coda", "glusterfs"} {
		if !remoteFS(fs) {
			t.Errorf("unexpected remote filesystem allowed: %s", fs)
		}
	}
	for _, fs := range []string{"ext4", "xfs", "btrfs", "zfs", "fuse.mergerfs"} {
		if remoteFS(fs) || pseudoFS(fs) {
			t.Errorf("local candidate filtered: %s", fs)
		}
	}
}

func testFilesystemMount(path string) filesystemMount {
	id := filesystemID(path, "device", "ext4", "/")
	return filesystemMount{resource: spec.FilesystemResource{Mount: path, Device: "device", Type: "ext4", ID: id}, identity: id}
}

func TestMergerfsMembershipRequiresCompleteExactEvidence(t *testing.T) {
	mounts := []filesystemMount{testFilesystemMount("/"), testFilesystemMount("/data"), testFilesystemMount("/mnt/one"), testFilesystemMount("/mnt/two space")}
	for _, raw := range []string{"/mnt/one:/mnt/two space", "/mnt/two space=RO,123:/mnt/one=RW", "/mnt/one=NC:/mnt/one=RW:/mnt/two space=RW"} {
		if got := mergerfsMemberMounts(raw, "/data", mounts); !reflect.DeepEqual(got, []string{"/mnt/one", "/mnt/two space"}) {
			t.Fatalf("bad membership for %q: %v", raw, got)
		}
	}
	for _, raw := range []string{"", "/mnt/one:/missing", "/mnt/one/subdir", "/mnt/*", "/data:/mnt/one", "/:/mnt/one", "/mnt/one=UNKNOWN", "/mnt/one:"} {
		if got := mergerfsMemberMounts(raw, "/data", mounts); got != nil {
			t.Fatalf("guessed membership for %q: %v", raw, got)
		}
	}
}

func TestFilesystemReadRejectsRemountAndStaleMembers(t *testing.T) {
	pool, member := testFilesystemMount("/data"), testFilesystemMount("/mnt/member")
	pool.resource.Pool = true
	for _, mode := range []string{"missing-before", "remounted-after", "member-removed", "xattr-error", "ok"} {
		t.Run(mode, func(t *testing.T) {
			calls, reads := 0, 0
			discover := func(context.Context) ([]filesystemMount, error) {
				calls++
				if mode == "missing-before" {
					return nil, nil
				}
				p := pool
				if mode == "remounted-after" && calls == 2 {
					p.identity = "replacement"
				}
				if mode == "member-removed" && calls == 2 {
					return []filesystemMount{p}, nil
				}
				return []filesystemMount{p, member}, nil
			}
			result, err := readVerifiedFilesystem(context.Background(), pool, discover, func(context.Context, string) (*disk.UsageStat, error) {
				reads++
				return &disk.UsageStat{Total: 100, Used: 10}, nil
			}, func(string) (string, error) {
				if mode == "xattr-error" {
					return "", errors.New("unavailable")
				}
				return "/mnt/member=RW", nil
			})
			if mode == "missing-before" || mode == "remounted-after" {
				if !errors.Is(err, errFilesystemChanged) || result.usage != nil {
					t.Fatal("mount replacement reported usable capacity")
				}
				if mode == "missing-before" && reads != 0 {
					t.Fatal("probed a disappeared mount")
				}
			} else {
				if err != nil || result.usage.Total != 100 {
					t.Fatal("valid usage discarded")
				}
				if mode == "ok" && len(result.members) != 1 {
					t.Fatal("confirmed membership missing")
				}
				if mode != "ok" && len(result.members) != 0 {
					t.Fatal("uncertain membership exposed")
				}
			}
		})
	}
}

func awaitFilesystem(t *testing.T, p *filesystemSampler, condition func([]spec.FilesystemResource) bool) []spec.FilesystemResource {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		value := p.snapshot(time.Now())
		if condition(value) {
			return value
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("filesystem collector did not settle")
	return nil
}

func TestFilesystemSamplerBoundsStuckCallsAndReservesRoot(t *testing.T) {
	mounts := []filesystemMount{testFilesystemMount("/")}
	for i := 0; i < 8; i++ {
		mounts = append(mounts, testFilesystemMount(fmt.Sprintf("/data%d", i)))
	}
	blocked := make(chan struct{})
	defer close(blocked)
	var dataCalls, rootCalls atomic.Int32
	p := &filesystemSampler{discover: func(context.Context) ([]filesystemMount, error) { return mounts, nil }, read: func(_ context.Context, mount filesystemMount, _ []filesystemMount) (filesystemRead, error) {
		if mount.resource.Mount != "/" {
			dataCalls.Add(1)
			<-blocked
		} else {
			rootCalls.Add(1)
		}
		return filesystemRead{usage: &disk.UsageStat{Total: 100, Used: 10}}, nil
	}}
	awaitFilesystem(t, p, func(fs []spec.FilesystemResource) bool {
		return len(fs) > 0 && fs[0].Total != nil && dataCalls.Load() == filesystemWorkers
	})
	started := time.Now()
	for i := 0; i < 100; i++ {
		p.snapshot(time.Now().Add(filesystemTimeout + time.Second))
	}
	if time.Since(started) > time.Second || dataCalls.Load() != filesystemWorkers {
		t.Fatal("heartbeat blocked or stuck calls multiplied")
	}
	p.mu.Lock()
	p.entries["/"].attempted = time.Now().Add(-filesystemInterval)
	p.mu.Unlock()
	awaitFilesystem(t, p, func([]spec.FilesystemResource) bool { return rootCalls.Load() >= 2 })
	if dataCalls.Load() != filesystemWorkers {
		t.Fatal("root refresh released blocked data slots")
	}
	// Replacing an entry cannot free its old syscall's global worker slot.
	p.mu.Lock()
	delete(p.entries, "/data0")
	replacement := testFilesystemMount("/replacement")
	p.entries["/replacement"] = &filesystemEntry{mount: replacement, value: replacement.resource}
	p.mu.Unlock()
	for i := 0; i < 100; i++ {
		p.snapshot(time.Now())
	}
	if dataCalls.Load() != filesystemWorkers {
		t.Fatal("remount bypassed worker bound")
	}
}

func TestFilesystemSamplerFreshnessFailureAndThrottle(t *testing.T) {
	var calls atomic.Int32
	var fail atomic.Bool
	p := &filesystemSampler{discover: func(context.Context) ([]filesystemMount, error) {
		return []filesystemMount{testFilesystemMount("/")}, nil
	}, read: func(context.Context, filesystemMount, []filesystemMount) (filesystemRead, error) {
		calls.Add(1)
		if fail.Load() {
			return filesystemRead{}, errors.New("failed")
		}
		return filesystemRead{usage: &disk.UsageStat{Total: 100, Used: 0}}, nil
	}}
	first := awaitFilesystem(t, p, func(fs []spec.FilesystemResource) bool { return len(fs) == 1 && fs[0].Total != nil })[0]
	if first.SampledAt == 0 || *first.Used != 0 {
		t.Fatal("zero is a valid successful measurement")
	}
	for i := 0; i < 100; i++ {
		p.snapshot(time.Now())
	}
	if calls.Load() != 1 {
		t.Fatal("capacity read was not throttled")
	}
	expired := p.snapshot(time.Now().Add(filesystemMaxAge + time.Second))[0]
	if expired.Total != nil || expired.SampledAt != first.SampledAt {
		t.Fatal("stale data fabricated a fresh sample")
	}
	fail.Store(true)
	p.mu.Lock()
	p.entries["/"].attempted = time.Now().Add(-filesystemInterval)
	p.mu.Unlock()
	failed := awaitFilesystem(t, p, func(fs []spec.FilesystemResource) bool {
		return len(fs) == 1 && fs[0].Total == nil && calls.Load() >= 2
	})[0]
	if failed.SampledAt != first.SampledAt {
		t.Fatal("failure refreshed the successful timestamp")
	}
	if first.Total == nil || *first.Total != 100 {
		t.Fatal("published snapshot was mutated")
	}
}

func TestFilesystemSamplerDiscoveryIsBounded(t *testing.T) {
	blocked := make(chan struct{})
	defer close(blocked)
	var calls atomic.Int32
	p := &filesystemSampler{discover: func(context.Context) ([]filesystemMount, error) { calls.Add(1); <-blocked; return nil, nil }}
	p.snapshot(time.Now())
	deadline := time.Now().Add(time.Second)
	for calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	for i := 0; i < 100; i++ {
		p.snapshot(time.Now().Add(time.Duration(i) * filesystemDiscoveryInterval))
	}
	if calls.Load() != 1 {
		t.Fatal("stuck discovery spawned duplicate workers")
	}
}

func TestFilesystemSamplerDrainsInventoryWithoutExtraHeartbeats(t *testing.T) {
	mounts := []filesystemMount{testFilesystemMount("/")}
	for i := 0; i < 20; i++ {
		mounts = append(mounts, testFilesystemMount(fmt.Sprintf("/data%d", i)))
	}
	var calls atomic.Int32
	p := &filesystemSampler{discover: func(context.Context) ([]filesystemMount, error) { return mounts, nil }, read: func(context.Context, filesystemMount, []filesystemMount) (filesystemRead, error) {
		calls.Add(1)
		return filesystemRead{usage: &disk.UsageStat{Total: 100, Used: 10}}, nil
	}}
	p.snapshot(time.Now())
	deadline := time.Now().Add(2 * time.Second)
	for calls.Load() < int32(len(mounts)) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if calls.Load() != int32(len(mounts)) {
		t.Fatalf("inventory queue stalled after %d calls", calls.Load())
	}
}

func TestFilesystemSamplerRejectsSuccessAfterDeadline(t *testing.T) {
	var slow atomic.Bool
	late := make(chan struct{})
	p := &filesystemSampler{discover: func(context.Context) ([]filesystemMount, error) {
		return []filesystemMount{testFilesystemMount("/")}, nil
	}, read: func(ctx context.Context, _ filesystemMount, _ []filesystemMount) (filesystemRead, error) {
		if slow.Load() {
			<-ctx.Done()
			close(late)
		}
		// A collector that ignores cancellation until returning may still
		// claim success. Its result must not become a fresh capacity sample.
		return filesystemRead{usage: &disk.UsageStat{Total: 100, Used: 10}}, nil
	}}
	first := awaitFilesystem(t, p, func(fs []spec.FilesystemResource) bool { return len(fs) == 1 && fs[0].Total != nil })[0]
	slow.Store(true)
	p.mu.Lock()
	p.entries["/"].attempted = time.Now().Add(-filesystemInterval)
	p.mu.Unlock()
	p.snapshot(time.Now())
	select {
	case <-late:
	case <-time.After(filesystemTimeout + time.Second):
		t.Fatal("read deadline did not expire")
	}
	last := awaitFilesystem(t, p, func(fs []spec.FilesystemResource) bool { return len(fs) == 1 && fs[0].Total == nil })[0]
	if last.SampledAt != first.SampledAt {
		t.Fatal("late success refreshed timestamp")
	}
}
