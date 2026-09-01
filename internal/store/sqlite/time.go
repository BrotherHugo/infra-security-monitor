package sqlite

import (
	"fmt"
	"time"
)

func formatTimeUTC(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

func parseTimeUTC(value string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("parsing time %q: %w", value, err)
	}
	return t.UTC(), nil
}
