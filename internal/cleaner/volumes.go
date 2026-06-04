package cleaner

import (
	"context"
	"log/slog"

	"github.com/danangamw/go-janitor/internal/runtime"
)

// RemoveOrphanedVolumes removes volumes not mounted by any container (active or stopped).
func RemoveOrphanedVolumes(ctx context.Context, cli runtime.ContainerRuntime, dryRun bool) (int, error) {
	volumes, err := cli.ListDanglingVolumes(ctx)
	if err != nil {
		return 0, err
	}

	removed := 0
	for _, v := range volumes {
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

		if err := cli.RemoveVolume(ctx, v.Name); err != nil {
			slog.Warn("failed to remove volume", "name", v.Name, "error", err)
			continue
		}
		removed++
		slog.Info("removed orphaned volume", "component", "cleaner", "action", "remove_volume", "resource_id", v.Name)
	}

	return removed, nil
}
