package scheduler

import (
	"context"
	"log/slog"
	"time"
)

// Runner runs one scheduled report cycle.
type Runner interface {
	RunCycle(ctx context.Context) error
}

// Scheduler wakes Runner at reporting.time slots.
type Scheduler struct {
	slots  []string
	loc    *time.Location
	now    func() time.Time
	runner Runner
}

// New creates a scheduler.
func New(slots []string, loc *time.Location, runner Runner) *Scheduler {
	if loc == nil {
		loc = time.Local
	}
	return &Scheduler{
		slots:  append([]string(nil), slots...),
		loc:    loc,
		now:    func() time.Time { return time.Now().UTC() },
		runner: runner,
	}
}

// SetNow overrides the clock (tests only).
func (s *Scheduler) SetNow(now func() time.Time) {
	if now != nil {
		s.now = now
	}
}

// Run waits for the next slot and calls Runner; exits on context cancellation.
func (s *Scheduler) Run(ctx context.Context) error {
	for {
		next, err := NextFire(s.now(), s.slots, s.loc)
		if err != nil {
			return err
		}

		wait := time.Until(next)
		slog.InfoContext(ctx, "scheduler: waiting for slot", "next", next.In(s.loc).Format(time.RFC3339), "wait", wait)

		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}

		if err := s.runner.RunCycle(ctx); err != nil {
			slog.ErrorContext(ctx, "scheduler: report cycle failed", "err", err)
		}
	}
}
