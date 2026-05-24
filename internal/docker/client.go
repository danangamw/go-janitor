package docker

import (
	"context"
	"fmt"

	"github.com/docker/docker/client"
)

// Client wraps the official Docker SDK client with a convenience constructor
// that connects via Unix socket.
type Client struct {
	*client.Client
}

// New creates a Docker client connected to the given Unix socket path.
// Caller must defer client.Close() after use.
func New(socketPath string) (*Client, error) {
	c, err := client.NewClientWithOpts(
		client.WithHost("unix://"+socketPath),
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return nil, fmt.Errorf("creating docker client on socket %q: %w", socketPath, err)
	}

	return &Client{c}, nil
}

// Ping verifies connectivity to the Docker daemon. Call this once at startup
// to surface permission errors early with a clear message.
func (c *Client) Ping(ctx context.Context) error {
	_, err := c.Client.Ping(ctx)
	if err != nil {
		return fmt.Errorf("cannot reach Docker daemon — ensure the socket is accessible and the user has permission: %w", err)
	}
	return nil
}
