//go:build !windows

package selfupdate

import "syscall"

// FreeSpace returns the bytes available to this process on the filesystem
// holding dir.
func FreeSpace(dir string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return uint64(st.Bavail) * uint64(st.Bsize), nil
}
