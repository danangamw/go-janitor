package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"
	"time"
)

// CVE represents a single vulnerability finding from Trivy.
type CVE struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	Severity         string `json:"Severity"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	Title            string `json:"Title"`
}

// ScanResult holds the outcome of scanning a single image.
type ScanResult struct {
	ImageID         string
	Vulnerabilities []CVE
	Error           string
	ScanDuration    time.Duration
}

// trivyOutput is the minimal shape of Trivy's JSON output we care about.
type trivyOutput struct {
	Results []struct {
		Vulnerabilities []CVE `json:"Vulnerabilities"`
	} `json:"Results"`
}

// scanImage runs `trivy image` for a single imageID and returns the result.
// All I/O is streamed via bufio.Scanner — no io.ReadAll.
func scanImage(ctx context.Context, imageID string, severity string) *ScanResult {
	start := time.Now()
	result := &ScanResult{ImageID: imageID}

	// #nosec G204 — imageID is sourced from Docker API, not user input
	cmd := exec.CommandContext(ctx, "trivy", "image",
		"--format", "json",
		"--severity", severity,
		"--quiet",
		imageID,
	)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		result.Error = fmt.Sprintf("stdout pipe: %v", err)
		result.ScanDuration = time.Since(start)
		return result
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		result.Error = fmt.Sprintf("stderr pipe: %v", err)
		result.ScanDuration = time.Since(start)
		return result
	}

	if err := cmd.Start(); err != nil {
		result.Error = fmt.Sprintf("start trivy: %v", err)
		result.ScanDuration = time.Since(start)
		return result
	}

	// Drain stderr asynchronously so it doesn't block stdout reads.
	go func() {
		s := bufio.NewScanner(stderr)
		for s.Scan() {
			slog.Debug("trivy stderr", "image", imageID, "line", s.Text())
		}
	}()

	// Stream and accumulate JSON output.
	var jsonBuf []byte
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		jsonBuf = append(jsonBuf, scanner.Bytes()...)
	}

	if err := cmd.Wait(); err != nil {
		// Trivy exits non-zero when vulnerabilities ARE found (exit 1) — that's expected.
		// Only treat it as a real error if we have no output at all.
		if len(jsonBuf) == 0 {
			result.Error = fmt.Sprintf("trivy exited: %v", err)
			result.ScanDuration = time.Since(start)
			return result
		}
	}

	var out trivyOutput
	if err := json.Unmarshal(jsonBuf, &out); err != nil {
		result.Error = fmt.Sprintf("parse trivy output: %v", err)
		result.ScanDuration = time.Since(start)
		return result
	}

	for _, r := range out.Results {
		result.Vulnerabilities = append(result.Vulnerabilities, r.Vulnerabilities...)
	}

	result.ScanDuration = time.Since(start)
	return result
}
