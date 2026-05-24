package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Report is the top-level JSON structure written to the output file.
type Report struct {
	RunID           string       `json:"run_id"`
	StartedAt       time.Time    `json:"started_at"`
	DurationSeconds float64      `json:"duration_seconds"`
	Cleaner         CleanerStats `json:"cleaner"`
	Scanner         ScannerStats `json:"scanner"`
}

type CleanerStats struct {
	ImagesRemoved     int   `json:"images_removed"`
	ContainersRemoved int   `json:"containers_removed"`
	VolumesRemoved    int   `json:"volumes_removed"`
	NetworksRemoved   int   `json:"networks_removed"`
	DiskFreedBytes    int64 `json:"disk_freed_bytes"`
}

type ScannerStats struct {
	ImagesScanned      int `json:"images_scanned"`
	ImagesWithCritical int `json:"images_with_critical"`
	ImagesWithHigh     int `json:"images_with_high"`
	ScanErrors         int `json:"scan_errors"`
	CacheHits          int `json:"cache_hits"`
}

// WriteJSON serialises the report to a file at path.
func WriteJSON(path string, r *Report) error {
	f, err := os.Create(path) // #nosec G304 — path is caller-controlled config value
	if err != nil {
		return fmt.Errorf("creating report file %q: %w", path, err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("encoding report: %w", err)
	}
	return nil
}
