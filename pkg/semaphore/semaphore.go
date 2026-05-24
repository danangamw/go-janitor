package semaphore

// Semaphore is a counting semaphore backed by a buffered channel.
type Semaphore chan struct{}

// New creates a semaphore with the given capacity.
func New(n int) Semaphore {
	return make(chan struct{}, n)
}

// Acquire blocks until a slot is available.
func (s Semaphore) Acquire() { s <- struct{}{} }

// Release frees a slot.
func (s Semaphore) Release() { <-s }
