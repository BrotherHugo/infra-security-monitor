package file

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/BrotherHugo/infra-security-monitor/internal/domain"
)

const channelName = "file"

// Channel writes the report to a directory on disk.
type Channel struct {
	saveToDir string
	location  *time.Location
	now       func() time.Time
}

// New creates a file channel.
func New(saveToDir string, location *time.Location) *Channel {
	loc := location
	if loc == nil {
		loc = time.Local
	}
	return &Channel{
		saveToDir: saveToDir,
		location:  loc,
		now:       time.Now,
	}
}

// Name returns the channel name.
func (c *Channel) Name() string {
	return channelName
}

// Send atomically writes the report to save_to_dir.
func (c *Channel) Send(ctx context.Context, report domain.TextReport) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if err := os.MkdirAll(c.saveToDir, 0o750); err != nil {
		return fmt.Errorf("file channel: mkdir %q: %w", c.saveToDir, err)
	}

	ts := report.GeneratedAt
	if ts.IsZero() {
		ts = c.now()
	}
	localTS := ts.In(c.location)
	filename := fmt.Sprintf("ism-report-%s.txt", localTS.Format("20060102-150405"))
	finalPath := filepath.Join(c.saveToDir, filename)
	tmpPath := filepath.Join(c.saveToDir, "."+filename+".tmp")

	if err := os.WriteFile(tmpPath, []byte(report.Body), 0o640); err != nil {
		return fmt.Errorf("file channel: write temp %q: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("file channel: rename %q: %w", finalPath, err)
	}
	return nil
}

// SetNow overrides the clock (tests only).
func (c *Channel) SetNow(now func() time.Time) {
	if now != nil {
		c.now = now
	}
}

// LastWrittenPath returns the last written file path for timestamping (tests only).
func (c *Channel) LastWrittenPath(report domain.TextReport) string {
	ts := report.GeneratedAt
	if ts.IsZero() {
		ts = c.now()
	}
	filename := fmt.Sprintf("ism-report-%s.txt", ts.In(c.location).Format("20060102-150405"))
	return filepath.Join(c.saveToDir, filename)
}
