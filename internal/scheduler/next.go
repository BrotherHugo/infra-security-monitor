package scheduler

import (
	"fmt"
	"sort"
	"time"
)

// NextFire returns the nearest slot time >= now (minute precision) in loc.
func NextFire(now time.Time, slots []string, loc *time.Location) (time.Time, error) {
	if len(slots) == 0 {
		return time.Time{}, fmt.Errorf("scheduler: empty time slot list")
	}
	if loc == nil {
		loc = time.Local
	}

	localNow := now.In(loc).Truncate(time.Minute)
	today := dateOnly(localNow)

	var candidates []time.Time
	for _, slot := range slots {
		slotTime, err := parseSlotTime(slot)
		if err != nil {
			return time.Time{}, err
		}
		candidate := time.Date(
			today.Year(), today.Month(), today.Day(),
			slotTime.Hour(), slotTime.Minute(), 0, 0, loc,
		)
		if !candidate.Before(localNow) {
			candidates = append(candidates, candidate)
		}
	}

	if len(candidates) > 0 {
		sort.Slice(candidates, func(i, j int) bool { return candidates[i].Before(candidates[j]) })
		return candidates[0], nil
	}

	tomorrow := today.AddDate(0, 0, 1)
	earliest, err := earliestSlotOnDay(tomorrow, slots, loc)
	if err != nil {
		return time.Time{}, err
	}
	return earliest, nil
}

func earliestSlotOnDay(day time.Time, slots []string, loc *time.Location) (time.Time, error) {
	var candidates []time.Time
	for _, slot := range slots {
		slotTime, err := parseSlotTime(slot)
		if err != nil {
			return time.Time{}, err
		}
		candidate := time.Date(
			day.Year(), day.Month(), day.Day(),
			slotTime.Hour(), slotTime.Minute(), 0, 0, loc,
		)
		candidates = append(candidates, candidate)
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Before(candidates[j]) })
	return candidates[0], nil
}

func parseSlotTime(slot string) (time.Time, error) {
	parsed, err := time.Parse("15:04", slot)
	if err != nil {
		return time.Time{}, fmt.Errorf("scheduler: slot %q is not in HH:MM format: %w", slot, err)
	}
	return parsed, nil
}

func dateOnly(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, t.Location())
}
