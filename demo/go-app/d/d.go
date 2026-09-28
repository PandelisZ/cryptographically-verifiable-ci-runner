// Package d sums numbers concurrently with golang.org/x/sync/errgroup.
package d

import (
	"sync/atomic"

	"golang.org/x/sync/errgroup"
)

// Sum adds xs up, one goroutine per element.
func Sum(xs []int) int {
	var g errgroup.Group
	var total atomic.Int64
	for _, x := range xs {
		g.Go(func() error {
			total.Add(int64(x))
			return nil
		})
	}
	_ = g.Wait()
	return int(total.Load())
}
