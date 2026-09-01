package scheduler_test

import (
	"testing"
	"time"

	"github.com/BrotherHugo/infra-security-monitor/internal/scheduler"
)

func TestNextFire_sameDayLaterSlot(t *testing.T) {
	loc := time.UTC
	now := time.Date(2026, 8, 13, 10, 0, 0, 0, loc)

	next, err := scheduler.NextFire(now, []string{"12:30", "18:00"}, loc)
	if err != nil {
		t.Fatalf("NextFire() error = %v", err)
	}
	want := time.Date(2026, 8, 13, 12, 30, 0, 0, loc)
	if !next.Equal(want) {
		t.Fatalf("next = %v, want %v", next, want)
	}
}

func TestNextFire_currentMinuteSlot(t *testing.T) {
	loc := time.UTC
	now := time.Date(2026, 8, 13, 12, 30, 15, 0, loc)

	next, err := scheduler.NextFire(now, []string{"12:30", "18:00"}, loc)
	if err != nil {
		t.Fatalf("NextFire() error = %v", err)
	}
	want := time.Date(2026, 8, 13, 12, 30, 0, 0, loc)
	if !next.Equal(want) {
		t.Fatalf("next = %v, want %v", next, want)
	}
}

func TestNextFire_nextDayEarliestSlot(t *testing.T) {
	loc := time.UTC
	now := time.Date(2026, 8, 13, 23, 0, 0, 0, loc)

	next, err := scheduler.NextFire(now, []string{"12:30", "08:00"}, loc)
	if err != nil {
		t.Fatalf("NextFire() error = %v", err)
	}
	want := time.Date(2026, 8, 14, 8, 0, 0, 0, loc)
	if !next.Equal(want) {
		t.Fatalf("next = %v, want %v", next, want)
	}
}
