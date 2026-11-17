package service

import (
	"errors"

	"github.com/lkarlslund/veksel/pkg/account"
)

// IsTemporarilyUnavailable classifies a fenced account without exposing the
// account lifecycle package to protocol implementations.
func IsTemporarilyUnavailable(err error) bool {
	return errors.Is(err, account.ErrTemporarilyUnavailable)
}
