//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd

package health

import "errors"

// OSCapacityProber makes unsupported platforms explicit in canonical health.
type OSCapacityProber struct{}

func (OSCapacityProber) Capacity(string) (Capacity, error) {
	return Capacity{}, errors.New("filesystem capacity probing is unsupported on this platform")
}
