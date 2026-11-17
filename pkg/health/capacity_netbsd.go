//go:build netbsd

package health

import (
	"fmt"
	"strconv"

	"golang.org/x/sys/unix"
)

// OSCapacityProber reads filesystem metadata from the host kernel.
type OSCapacityProber struct{}

func (OSCapacityProber) Capacity(path string) (Capacity, error) {
	var filesystem unix.Statvfs_t
	if err := unix.Statvfs(path, &filesystem); err != nil {
		return Capacity{}, fmt.Errorf("inspect filesystem: %w", err)
	}
	var file unix.Stat_t
	if err := unix.Stat(path, &file); err != nil {
		return Capacity{}, fmt.Errorf("identify filesystem: %w", err)
	}
	blockSize := uint64(filesystem.Frsize)
	return Capacity{
		DeviceID:       strconv.FormatUint(uint64(file.Dev), 10),
		TotalBytes:     saturatedMultiply(filesystem.Blocks, blockSize),
		AvailableBytes: saturatedMultiply(filesystem.Bavail, blockSize),
	}, nil
}
