package cleaner

import (
	"context"
	"log/slog"
	"time"

	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	dockerclient "github.com/docker/docker/client"
)

// RemoveDanglingImages removes images with no tag and no referencing container.
// Returns the total bytes freed.
func RemoveDanglingImages(ctx context.Context, cli *dockerclient.Client, dryRun bool) (int64, int, error) {
	f := filters.NewArgs(filters.Arg("dangling", "true"))
	images, err := cli.ImageList(ctx, image.ListOptions{Filters: f})
	if err != nil {
		return 0, 0, err
	}

	var freed int64
	var removed int

	for _, img := range images {
		prefix := ""
		if dryRun {
			prefix = "[DRY-RUN] "
		}
		slog.Info(prefix+"would remove dangling image",
			"component", "cleaner",
			"action", "remove_image",
			"resource_id", img.ID,
			"size_bytes", img.Size,
		)

		if dryRun {
			freed += img.Size
			removed++
			continue
		}

		_, err := cli.ImageRemove(ctx, img.ID, image.RemoveOptions{Force: false, PruneChildren: true})
		if err != nil {
			slog.Warn("failed to remove image", "id", img.ID, "error", err)
			continue
		}
		freed += img.Size
		removed++
		slog.Info("removed dangling image", "component", "cleaner", "action", "remove_image", "resource_id", img.ID)
	}

	return freed, removed, nil
}

// RemoveStoppedContainers removes containers in exited/dead state older than maxAge.
// Returns bytes freed and count removed.
func RemoveStoppedContainers(ctx context.Context, cli *dockerclient.Client, maxAge time.Duration, dryRun bool) (int64, int, error) {
	f := filters.NewArgs(
		filters.Arg("status", "exited"),
		filters.Arg("status", "dead"),
	)
	containers, err := cli.ContainerList(ctx, containerListOptions(f))
	if err != nil {
		return 0, 0, err
	}

	cutoff := time.Now().Add(-maxAge)
	var freed int64
	var removed int

	for _, c := range containers {
		created := time.Unix(c.Created, 0)
		if created.After(cutoff) {
			slog.Debug("skipping container — not old enough", "id", c.ID, "created", created)
			continue
		}

		prefix := ""
		if dryRun {
			prefix = "[DRY-RUN] "
		}
		slog.Info(prefix+"would remove stopped container",
			"component", "cleaner",
			"action", "remove_container",
			"resource_id", c.ID,
			"image", c.Image,
			"created", created,
		)

		if dryRun {
			removed++
			continue
		}

		// Inspect to get size before removal
		inspect, err := cli.ContainerInspect(ctx, c.ID)
		if err == nil && inspect.SizeRootFs != nil {
			freed += *inspect.SizeRootFs
		}

		if err := cli.ContainerRemove(ctx, c.ID, containerRemoveOptions()); err != nil {
			slog.Warn("failed to remove container", "id", c.ID, "error", err)
			continue
		}
		removed++
		slog.Info("removed stopped container", "component", "cleaner", "action", "remove_container", "resource_id", c.ID)
	}

	return freed, removed, nil
}
