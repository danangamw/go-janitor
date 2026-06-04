package runtime

import (
	"context"
	"fmt"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/volume"
	dockerclient "github.com/docker/docker/client"
)

// DockerRuntime wraps the Docker SDK and implements ContainerRuntime.
type DockerRuntime struct {
	cli *dockerclient.Client
}

// NewDockerRuntime creates a Docker client connected to the given Unix socket path.
func NewDockerRuntime(socketPath string) (*DockerRuntime, error) {
	c, err := dockerclient.NewClientWithOpts(
		dockerclient.WithHost("unix://"+socketPath),
		dockerclient.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return nil, fmt.Errorf("creating docker client on socket %q: %w", socketPath, err)
	}

	return &DockerRuntime{cli: c}, nil
}

// Ping verifies connectivity to the container daemon.
func (d *DockerRuntime) Ping(ctx context.Context) error {
	_, err := d.cli.Ping(ctx)
	if err != nil {
		return fmt.Errorf("cannot reach container daemon — ensure the socket is accessible: %w", err)
	}
	return nil
}

// Close closes the underlying client connection.
func (d *DockerRuntime) Close() error {
	return d.cli.Close()
}

// ListDanglingImages retrieves images with no tags.
func (d *DockerRuntime) ListDanglingImages(ctx context.Context) ([]Image, error) {
	f := filters.NewArgs(filters.Arg("dangling", "true"))
	images, err := d.cli.ImageList(ctx, image.ListOptions{Filters: f})
	if err != nil {
		return nil, err
	}

	var res []Image
	for _, img := range images {
		res = append(res, Image{
			ID:   img.ID,
			Size: img.Size,
		})
	}
	return res, nil
}

// RemoveImage removes an image by its ID.
func (d *DockerRuntime) RemoveImage(ctx context.Context, imageID string) error {
	_, err := d.cli.ImageRemove(ctx, imageID, image.RemoveOptions{Force: false, PruneChildren: true})
	return err
}

// ListContainers lists containers.
func (d *DockerRuntime) ListContainers(ctx context.Context, all bool) ([]Container, error) {
	containers, err := d.cli.ContainerList(ctx, container.ListOptions{All: all})
	if err != nil {
		return nil, err
	}

	var res []Container
	for _, c := range containers {
		res = append(res, Container{
			ID:      c.ID,
			Names:   c.Names,
			Image:   c.Image,
			ImageID: c.ImageID,
			Created: c.Created,
			State:   c.State,
		})
	}
	return res, nil
}

// GetContainerSize inspects a container to retrieve its RootFS size.
func (d *DockerRuntime) GetContainerSize(ctx context.Context, containerID string) (int64, error) {
	inspect, err := d.cli.ContainerInspect(ctx, containerID)
	if err != nil {
		return 0, err
	}
	if inspect.SizeRootFs != nil {
		return *inspect.SizeRootFs, nil
	}
	return 0, nil
}

// RemoveContainer removes a container by its ID.
func (d *DockerRuntime) RemoveContainer(ctx context.Context, containerID string) error {
	return d.cli.ContainerRemove(ctx, containerID, container.RemoveOptions{RemoveVolumes: false, Force: false})
}

// ListDanglingVolumes lists volumes that are not attached to any container.
func (d *DockerRuntime) ListDanglingVolumes(ctx context.Context) ([]Volume, error) {
	f := filters.NewArgs(filters.Arg("dangling", "true"))
	resp, err := d.cli.VolumeList(ctx, volume.ListOptions{Filters: f})
	if err != nil {
		return nil, err
	}

	var res []Volume
	for _, v := range resp.Volumes {
		res = append(res, Volume{
			Name:   v.Name,
			Driver: v.Driver,
		})
	}
	return res, nil
}

// RemoveVolume removes a volume by its name.
func (d *DockerRuntime) RemoveVolume(ctx context.Context, volumeName string) error {
	return d.cli.VolumeRemove(ctx, volumeName, false)
}

// ListNetworks lists all networks.
func (d *DockerRuntime) ListNetworks(ctx context.Context) ([]Network, error) {
	networks, err := d.cli.NetworkList(ctx, network.ListOptions{})
	if err != nil {
		return nil, err
	}

	var res []Network
	for _, n := range networks {
		res = append(res, Network{
			ID:             n.ID,
			Name:           n.Name,
			Driver:         n.Driver,
			ContainerCount: len(n.Containers),
		})
	}
	return res, nil
}

// RemoveNetwork removes a network by its ID.
func (d *DockerRuntime) RemoveNetwork(ctx context.Context, networkID string) error {
	return d.cli.NetworkRemove(ctx, networkID)
}
