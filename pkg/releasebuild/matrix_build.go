package releasebuild

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

type matrixBuilder func(context.Context, BuildOptions) (Fragment, error)

// BuildMatrix builds a validated matrix with a bounded worker pool on one
// machine. Results retain canonical matrix order even when builds finish out of
// order, and the first failure cancels outstanding work.
func BuildMatrix(ctx context.Context, matrix Matrix, options BuildOptions, parallel int) ([]Fragment, error) {
	return buildMatrix(ctx, matrix, options, parallel, BuildOne)
}

func buildMatrix(ctx context.Context, matrix Matrix, options BuildOptions, parallel int, build matrixBuilder) ([]Fragment, error) {
	if err := ValidateMatrix(matrix, false); err != nil {
		return nil, err
	}
	if len(matrix.Include) == 0 {
		return nil, errors.New("build matrix is empty")
	}
	if parallel < 1 {
		return nil, errors.New("parallel build count must be positive")
	}
	parallel = min(parallel, len(matrix.Include))

	workerContext, cancel := context.WithCancel(ctx)
	defer cancel()
	type task struct {
		index int
		entry MatrixEntry
	}
	tasks := make(chan task)
	results := make([]Fragment, len(matrix.Include))
	var workers sync.WaitGroup
	var firstError error
	var errorOnce sync.Once
	for range parallel {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for task := range tasks {
				entryOptions := options
				entryOptions.GOOS = task.entry.GOOS
				entryOptions.GOARCH = task.entry.GOARCH
				entryOptions.Variant = task.entry.Variant
				fragment, err := build(workerContext, entryOptions)
				if err != nil {
					errorOnce.Do(func() {
						firstError = fmt.Errorf("build %s/%s (%s): %w", task.entry.GOOS, task.entry.GOARCH, task.entry.Variant, err)
						cancel()
					})
					continue
				}
				results[task.index] = fragment
			}
		}()
	}

send:
	for index, entry := range matrix.Include {
		select {
		case <-workerContext.Done():
			break send
		case tasks <- task{index: index, entry: entry}:
		}
	}
	close(tasks)
	workers.Wait()
	if firstError != nil {
		return nil, firstError
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return results, nil
}
