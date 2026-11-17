//go:build freebsd || openbsd

package health

func nonNegative(value int64) uint64 {
	if value < 0 {
		return 0
	}
	return uint64(value)
}
