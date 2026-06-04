package reporter

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"
)

// ScanRow holds clean representation of a scan result for formatting
type ScanRow struct {
	ImageID      string
	Vulns        int
	HasCritical  bool
	HasHigh      bool
	DurationMs   int64
	Error        string
}

// PrintScanTable outputs a formatted table of security scan results to stdout
func PrintScanTable(version string, rows []ScanRow, stats ScannerStats, severity string, concurrency int) {
	nowStr := time.Now().Format("2006-01-02 15:04:05")
	fmt.Println()
	fmt.Printf("\033[1;36mgo-janitor %s\033[0m · Security Audit · %s\n\n", version, nowStr)
	fmt.Printf("  Scanning %d images (concurrency: %d, severity: %s)\n\n", len(rows), concurrency, severity)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	// Header
	fmt.Fprintln(w, "  \033[1mIMAGE\033[0m\t\033[1mVULNS\033[0m\t\033[1mSEVERITY\033[0m\t\033[1mTIME\033[0m")
	fmt.Fprintln(w, "  \033[1m─────────────────────────────────────────────────────\033[0m")

	for _, r := range rows {
		// Truncate image ID to make it fit nicely
		imgID := r.ImageID
		if strings.HasPrefix(imgID, "sha256:") && len(imgID) > 19 {
			imgID = imgID[:19] + "..."
		} else if len(imgID) > 12 {
			imgID = imgID[:12] + "..."
		}

		timeStr := fmt.Sprintf("%.2fs", float64(r.DurationMs)/1000.0)

		var statusStr string
		var vulnStr string
		if r.Error != "" {
			vulnStr = "-"
			statusStr = fmt.Sprintf("\033[1;31m✗ Error: %s\033[0m", r.Error)
		} else if r.Vulns == 0 {
			vulnStr = "0"
			statusStr = "\033[1;32m✓ Clean\033[0m"
		} else {
			vulnStr = fmt.Sprintf("%d", r.Vulns)
			if r.HasCritical {
				statusStr = "\033[1;31m✗ CRITICAL\033[0m"
			} else if r.HasHigh {
				statusStr = "\033[1;33m⚠ HIGH\033[0m"
			} else {
				statusStr = "\033[1;33m⚠ WARNING\033[0m"
			}
		}

		fmt.Fprintf(w, "  %s\t%s\t%s\t%s\n", imgID, vulnStr, statusStr, timeStr)
	}

	fmt.Fprintln(w, "  \033[1m─────────────────────────────────────────────────────\033[0m")
	w.Flush()

	// Print summary line
	fmt.Printf("  Scanned: \033[1m%d\033[0m   Critical: \033[1;31m%d\033[0m   High: \033[1;33m%d\033[0m   Errors: \033[1;31m%d\033[0m   Cache Hits: \033[1m%d\033[0m\n\n",
		stats.ImagesScanned, stats.ImagesWithCritical, stats.ImagesWithHigh, stats.ScanErrors, stats.CacheHits)
}

// PrintCleanerSummary outputs a formatted summary of trash collection results to stdout
func PrintCleanerSummary(version string, stats CleanerStats, maxAge time.Duration, dryRun bool) {
	nowStr := time.Now().Format("2006-01-02 15:04:05")
	fmt.Println()
	prefix := ""
	if dryRun {
		prefix = "\033[1;33m[DRY-RUN] \033[0m"
	}
	fmt.Printf("%s\033[1;36mgo-janitor %s\033[0m · Trash Collector · %s\n\n", prefix, version, nowStr)
	fmt.Printf("  Removing dangling resources (max-age: %s)...\n\n", maxAge)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "  \033[1mTYPE\033[0m\t\033[1mREMOVED\033[0m\t\033[1mSTATUS\033[0m")
	fmt.Fprintln(w, "  \033[1m──────────────────────────────────\033[0m")

	printRow := func(resourceType string, count int, extra string) {
		status := "\033[1;32m✓ Clean\033[0m"
		if count > 0 {
			if extra != "" {
				status = fmt.Sprintf("\033[1;32m✓ Freed %s\033[0m", extra)
			} else {
				status = "\033[1;32m✓ Removed\033[0m"
			}
		}
		fmt.Fprintf(w, "  %s\t%d\t%s\n", resourceType, count, status)
	}

	freedStr := formatBytes(stats.DiskFreedBytes)

	printRow("Images", stats.ImagesRemoved, freedStr)
	printRow("Containers", stats.ContainersRemoved, "")
	printRow("Volumes", stats.VolumesRemoved, "")
	printRow("Networks", stats.NetworksRemoved, "")

	fmt.Fprintln(w, "  \033[1m──────────────────────────────────\033[0m")
	w.Flush()

	fmt.Printf("  Total Disk Space Freed: \033[1;32m%s\033[0m\n\n", freedStr)
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
