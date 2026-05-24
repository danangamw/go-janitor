package scanner

import (
	"context"
	"log/slog"
	"os/exec"

	"github.com/docker/docker/api/types/container"
	dockerclient "github.com/docker/docker/client"
	"golang.org/x/sync/errgroup"

	"github.com/danangamw/go-janitor/internal/reporter"
	"github.com/danangamw/go-janitor/pkg/semaphore"
)

// Run orchestrates parallel security scanning of all running container images.
// It deduplicates images, limits concurrency via semaphore, and handles partial failures.
func Run(ctx context.Context, cli *dockerclient.Client, severity string, concurrency int) (reporter.ScannerStats, []*ScanResult) {
	var stats reporter.ScannerStats

	// Check trivy is available.
	if _, err := exec.LookPath("trivy"); err != nil {
		slog.Error("trivy binary not found — install trivy to enable security scanning",
			"hint", "https://aquasecurity.github.io/trivy/latest/getting-started/installation/")
		return stats, nil
	}

	containers, err := cli.ContainerList(ctx, container.ListOptions{All: false})
	if err != nil {
		slog.Error("failed to list running containers", "error", err)
		return stats, nil
	}

	// Deduplicate image IDs.
	seen := make(map[string]bool)
	var uniqueImages []string
	for _, c := range containers {
		id := c.ImageID
		if !seen[id] {
			seen[id] = true
			uniqueImages = append(uniqueImages, id)
		}
	}

	slog.Info("starting security auditor",
		"component", "scanner",
		"unique_images", len(uniqueImages),
		"concurrency", concurrency,
		"severity", severity,
	)

	imgCache := newCache()
	sem := semaphore.New(concurrency)

	results := make([]*ScanResult, len(uniqueImages))

	g, gctx := errgroup.WithContext(ctx)

	for i, imageID := range uniqueImages {
		i, imageID := i, imageID // capture loop variables

		g.Go(func() error {
			// Check cache first.
			if cached, ok := imgCache.get(imageID); ok {
				slog.Info("cache hit — skipping re-scan",
					"component", "scanner",
					"action", "cache_hit",
					"resource_id", imageID,
				)
				stats.CacheHits++
				results[i] = cached
				return nil
			}

			sem.Acquire()
			defer sem.Release()

			slog.Info("scanning image",
				"component", "scanner",
				"action", "scan_start",
				"resource_id", imageID,
			)

			r := scanImage(gctx, imageID, severity)
			imgCache.set(imageID, r)
			results[i] = r

			if r.Error != "" {
				slog.Warn("scan error",
					"component", "scanner",
					"resource_id", imageID,
					"error", r.Error,
					"duration_ms", r.ScanDuration.Milliseconds(),
				)
				return nil // partial failure — continue other scans
			}

			hasCritical := false
			hasHigh := false
			for _, v := range r.Vulnerabilities {
				if v.Severity == "CRITICAL" {
					hasCritical = true
				}
				if v.Severity == "HIGH" {
					hasHigh = true
				}
			}

			slog.Info("scan complete",
				"component", "scanner",
				"action", "scan_done",
				"resource_id", imageID,
				"vulnerabilities", len(r.Vulnerabilities),
				"duration_ms", r.ScanDuration.Milliseconds(),
			)

			if hasCritical {
				stats.ImagesWithCritical++
			}
			if hasHigh {
				stats.ImagesWithHigh++
			}

			return nil
		})
	}

	// errgroup never returns a real error here (we swallow per-scan errors above),
	// but we still wait for all goroutines.
	_ = g.Wait()

	stats.ImagesScanned = len(uniqueImages)
	for _, r := range results {
		if r != nil && r.Error != "" {
			stats.ScanErrors++
		}
	}

	slog.Info("security auditor finished",
		"component", "scanner",
		"images_scanned", stats.ImagesScanned,
		"images_with_critical", stats.ImagesWithCritical,
		"images_with_high", stats.ImagesWithHigh,
		"scan_errors", stats.ScanErrors,
		"cache_hits", stats.CacheHits,
	)

	return stats, results
}
