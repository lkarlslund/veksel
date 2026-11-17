package jsonstore

import "context"

type viewContextKey struct{}

type viewState struct {
	store *Store
}

func (s *Store) activeView(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	state, _ := ctx.Value(viewContextKey{}).(viewState)
	return state.store == s
}

// View holds one shared lock across related reads so a backup or query cannot
// observe keys from different points in time.
func (s *Store) View(ctx context.Context, fn func(context.Context) error) error {
	if s.activeBatch(ctx) != nil || s.activeView(ctx) {
		return fn(ctx)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	unlock, err := s.rlock()
	if err != nil {
		return err
	}
	defer unlock()
	return fn(context.WithValue(ctx, viewContextKey{}, viewState{store: s}))
}
