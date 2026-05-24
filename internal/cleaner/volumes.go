package cleaner

import (
	"context"
	"log/slog"

	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/volume"
	dockerclient "github.com/docker/docker/client"
)

// RemoveOrphanedVolumes removes volumes not mounted by any container (active or stopped).
func RemoveOrphanedVolumes(ctx context.Context, cli *dockerclient.Client, dryRun bool) (int, error) {
	f := filters.NewArgs(filters.Arg("dangling", "true"))
	resp, err := cli.VolumeList(ctx, volume.ListOptions{Filters: f})
	if err != nil {
		return 0, err
	}

	removed := 0
	for _, v := range resp.Volumes {
		prefix := ""
		if dryRun {
			prefix = "[DRY-RUN] "
		}
		slog.Info(prefix+"would remove orphaned volume",
			"component", "cleaner",
			"action", "remove_volume",
			"resource_id", v.Name,
			"driver", v.Driver,
		)

		if dryRun {
			removed++
			continue
		}

		if err := cli.VolumeRemove(ctx, v.Name, false); err != nil {
			slog.Warn("failed to remove volume", "name", v.Name, "error", err)
			continue
		}
		removed++
		slog.Info("removed orphaned volume", "component", "cleaner", "action", "remove_volume", "resource_id", v.Name)
	}

	return removed, nil
}
