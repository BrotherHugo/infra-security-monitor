package fail2ban

import (
	"fmt"
	"strconv"
	"strings"
)

// ParseStatus parses fail2ban-client status stdout for tests and debugging.
func ParseStatus(stdout, expectedJail string) (JailStatus, error) {
	return parseStatus(stdout, expectedJail)
}

type JailStatus struct {
	Name             string   `json:"name"`
	CurrentlyFailed  int      `json:"currently_failed"`
	TotalFailed      int      `json:"total_failed"`
	CurrentlyBanned  int      `json:"currently_banned"`
	TotalBanned      int      `json:"total_banned"`
	BannedIPs        []string `json:"banned_ips"`
}

func parseStatus(stdout, expectedJail string) (JailStatus, error) {
	var stat JailStatus
	foundJail := false

	for _, line := range strings.Split(stdout, "\n") {
		line = normalizeLine(line)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "Status for the jail:") {
			name := strings.TrimSpace(strings.TrimPrefix(line, "Status for the jail:"))
			if name == "" {
				return JailStatus{}, fmt.Errorf("empty jail name in output")
			}
			stat.Name = name
			foundJail = true
			continue
		}

		if value, ok := parseLabeledInt(line, "Currently failed:"); ok {
			stat.CurrentlyFailed = value
			continue
		}
		if value, ok := parseLabeledInt(line, "Total failed:"); ok {
			stat.TotalFailed = value
			continue
		}
		if value, ok := parseLabeledInt(line, "Currently banned:"); ok {
			stat.CurrentlyBanned = value
			continue
		}
		if value, ok := parseLabeledInt(line, "Total banned:"); ok {
			stat.TotalBanned = value
			continue
		}
		if strings.HasPrefix(line, "Banned IP list:") {
			stat.BannedIPs = parseBannedIPs(line)
		}
	}

	if !foundJail {
		return JailStatus{}, fmt.Errorf("Status for the jail line not found")
	}
	if stat.Name != expectedJail {
		return JailStatus{}, fmt.Errorf("expected jail %q, got %q", expectedJail, stat.Name)
	}
	return stat, nil
}

func normalizeLine(line string) string {
	line = strings.TrimSpace(line)
	line = strings.TrimLeft(line, "|`-\t ")
	return strings.TrimSpace(line)
}

func parseLabeledInt(line, label string) (int, bool) {
	if !strings.HasPrefix(line, label) {
		return 0, false
	}
	raw := strings.TrimSpace(strings.TrimPrefix(line, label))
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, false
	}
	return value, true
}

func parseBannedIPs(line string) []string {
	raw := strings.TrimSpace(strings.TrimPrefix(line, "Banned IP list:"))
	if raw == "" {
		return nil
	}
	return strings.Fields(raw)
}
