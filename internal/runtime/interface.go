package runtime

import (
	"context"
)

// Container represents standard metadata of a container.
type Container struct {
	ID      string
	Names   []string
	Image   string
	ImageID string
	Created int64 // Unix timestamp
	State   string
}

// Image represents standard metadata of an image.
type Image struct {
	ID   string
	Size int64
}

// Volume represents standard metadata of a storage volume.
type Volume struct {
	Name   string
	Driver string
}

// Network represents standard network metadata.
type Network struct {
	ID             string
	Name           string
	Driver         string
	ContainerCount int
}

// ContainerRuntime decouples cleaning and scanning logic from the underlying container engine.
type ContainerRuntime interface {
	Ping(ctx context.Context) error
	Close() error

	// Image operations
	ListDanglingImages(ctx context.Context) ([]Image, error)
	RemoveImage(ctx context.Context, imageID string) error

	// Container operations
	ListContainers(ctx context.Context, all bool) ([]Container, error)
	GetContainerSize(ctx context.Context, containerID string) (int64, error)
	RemoveContainer(ctx context.Context, containerID string) error

	// Volume operations
	ListDanglingVolumes(ctx context.Context) ([]Volume, error)
	RemoveVolume(ctx context.Context, volumeName string) error

	// Network operations
	ListNetworks(ctx context.Context) ([]Network, error)
	RemoveNetwork(ctx context.Context, networkID string) error
}
