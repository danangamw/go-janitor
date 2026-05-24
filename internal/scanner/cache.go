package scanner

import (
	"sync"
)

// cache stores scan results per image ID to avoid duplicate Trivy executions.
type cache struct {
	mu    sync.Mutex
	store map[string]*ScanResult
}

func newCache() *cache {
	return &cache{store: make(map[string]*ScanResult)}
}

// get returns the cached result and true if it exists.
func (c *cache) get(imageID string) (*ScanResult, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	r, ok := c.store[imageID]
	return r, ok
}

// set stores a result for the given image ID.
func (c *cache) set(imageID string, r *ScanResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.store[imageID] = r
}
