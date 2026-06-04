package cleaner

import (
	"context"
	"log/slog"
	"time"

	"github.com/danangamw/go-janitor/internal/runtime"
)

// RemoveDanglingImages removes images with no tag and no referencing container.
// Returns the total bytes freed.
func RemoveDanglingImages(ctx context.Context, cli runtime.ContainerRuntime, dryRun bool) (int64, int, error) {
	images, err := cli.ListDanglingImages(ctx)
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

		err := cli.RemoveImage(ctx, img.ID)
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
func RemoveStoppedContainers(ctx context.Context, cli runtime.ContainerRuntime, maxAge time.Duration, dryRun bool) (int64, int, error) {
	containers, err := cli.ListContainers(ctx, true)
	if err != nil {
		return 0, 0, err
	}

	cutoff := time.Now().Add(-maxAge)
	var freed int64
	var removed int

	for _, c := range containers {
		if c.State != "exited" && c.State != "dead" {
			continue
		}

		created := time.Unix(c.Created, 0)
		if created.After(cutoff) {
			slog.Debug("skipping container — not old enough", "id", c.ID, "created", created)
			continue
		}

		prefix := ""
		if dryRun {
			prefix = "[DRY-RUN] "
		}

		var cName string
		if len(c.Names) > 0 {
			cName = c.Names[0]
		} else {
			cName = c.ID
		}

		slog.Info(prefix+"would remove stopped container",
			"component", "cleaner",
			"action", "remove_container",
			"resource_id", c.ID,
			"name", cName,
			"image", c.Image,
			"created", created,
		)

		if dryRun {
			removed++
			continue
		}

		// Get size before removal
		size, err := cli.GetContainerSize(ctx, c.ID)
		if err == nil {
			freed += size
		}

		if err := cli.RemoveContainer(ctx, c.ID); err != nil {
			slog.Warn("failed to remove container", "id", c.ID, "error", err)
			continue
		}
		removed++
		slog.Info("removed stopped container", "component", "cleaner", "action", "remove_container", "resource_id", c.ID)
	}

	return freed, removed, nil
}
