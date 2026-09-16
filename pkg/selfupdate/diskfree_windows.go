//go:build windows

package selfupdate

import "errors"

// FreeSpace is not implemented on Windows; callers skip the check.
func FreeSpace(dir string) (uint64, error) { return 0, errors.New("free space: unsupported") }
