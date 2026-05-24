package cleaner

import (
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
)

// containerListOptions builds ContainerListOptions from a filter (avoids import cycles).
func containerListOptions(f filters.Args) container.ListOptions {
	return container.ListOptions{All: true, Filters: f}
}

// containerRemoveOptions returns default removal options for stopped containers.
func containerRemoveOptions() container.RemoveOptions {
	return container.RemoveOptions{RemoveVolumes: false, Force: false}
}
