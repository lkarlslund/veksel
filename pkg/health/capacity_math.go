package health

import "math"

func saturatedMultiply(left, right uint64) uint64 {
	if right != 0 && left > math.MaxUint64/right {
		return math.MaxUint64
	}
	return left * right
}
