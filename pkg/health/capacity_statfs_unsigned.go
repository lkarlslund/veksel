//go:build linux || darwin

package health

import (
	"fmt"
	"strconv"

	"golang.org/x/sys/unix"
)

// OSCapacityProber reads filesystem metadata from the host kernel.
type OSCapacityProber struct{}

func (OSCapacityProber) Capacity(path string) (Capacity, error) {
	var filesystem unix.Statfs_t
	if err := unix.Statfs(path, &filesystem); err != nil {
		return Capacity{}, fmt.Errorf("inspect filesystem: %w", err)
	}
	var file unix.Stat_t
	if err := unix.Stat(path, &file); err != nil {
		return Capacity{}, fmt.Errorf("identify filesystem: %w", err)
	}
	blockSize := uint64(filesystem.Bsize)
	return Capacity{
		DeviceID:       strconv.FormatUint(uint64(file.Dev), 10),
		TotalBytes:     saturatedMultiply(uint64(filesystem.Blocks), blockSize),
		AvailableBytes: saturatedMultiply(uint64(filesystem.Bavail), blockSize),
	}, nil
}
