package cleaner

import (
	"context"
	"log/slog"
	"time"

	"github.com/danangamw/go-janitor/internal/reporter"
	"github.com/danangamw/go-janitor/internal/runtime"
)

// Run executes the full Trash Collector pipeline and returns aggregated stats.
func Run(ctx context.Context, cli runtime.ContainerRuntime, maxAge time.Duration, dryRun bool) reporter.CleanerStats {
	var stats reporter.CleanerStats

	slog.Info("starting trash collector", "component", "cleaner", "dry_run", dryRun, "max_age", maxAge)

	freed, removed, err := RemoveDanglingImages(ctx, cli, dryRun)
	if err != nil {
		slog.Error("image cleanup failed", "component", "cleaner", "error", err)
	}
	stats.ImagesRemoved = removed
	stats.DiskFreedBytes += freed

	cFreed, cRemoved, err := RemoveStoppedContainers(ctx, cli, maxAge, dryRun)
	if err != nil {
		slog.Error("container cleanup failed", "component", "cleaner", "error", err)
	}
	stats.ContainersRemoved = cRemoved
	stats.DiskFreedBytes += cFreed

	vRemoved, err := RemoveOrphanedVolumes(ctx, cli, dryRun)
	if err != nil {
		slog.Error("volume cleanup failed", "component", "cleaner", "error", err)
	}
	stats.VolumesRemoved = vRemoved

	nRemoved, err := RemoveUnusedNetworks(ctx, cli, dryRun)
	if err != nil {
		slog.Error("network cleanup failed", "component", "cleaner", "error", err)
	}
	stats.NetworksRemoved = nRemoved

	slog.Info("trash collector finished",
		"component", "cleaner",
		"images_removed", stats.ImagesRemoved,
		"containers_removed", stats.ContainersRemoved,
		"volumes_removed", stats.VolumesRemoved,
		"networks_removed", stats.NetworksRemoved,
		"disk_freed_bytes", stats.DiskFreedBytes,
	)
	return stats
}
