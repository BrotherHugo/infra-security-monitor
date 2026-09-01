package googleai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/BrotherHugo/infra-security-monitor/internal/analyze"
	"github.com/BrotherHugo/infra-security-monitor/internal/domain"
)

const (
	maxPayloadRunes      = 900_000
	truncationWarning    = "WARNING: payload truncated due to size limit; some raw blobs were shortened.\n"
	truncatedBlobSuffix  = "\n[... truncated ...]"
)

type moduleSection struct {
	name        string
	headerLines string
	blobs       map[string]string
}

func buildUserPayload(in analyze.Input) string {
	byName := make(map[string]domain.ModuleResult, len(in.Results))
	for _, result := range in.Results {
		byName[string(result.Name)] = result
	}

	sections := make([]moduleSection, 0, len(in.ModuleOrder))
	for _, name := range in.ModuleOrder {
		result, ok := byName[name]
		if !ok {
			sections = append(sections, moduleSection{
				name:        name,
				headerLines: moduleHeaderLines(name, nil, false),
			})
			continue
		}
		sections = append(sections, moduleSection{
			name:        name,
			headerLines: moduleHeaderLines(name, &result, true),
			blobs:       parseRawBlobs(result.Raw),
		})
	}

	payload := assemblePayload(in, sections, false)
	if utf8.RuneCountInString(payload) <= maxPayloadRunes {
		return payload
	}

	truncateSections(in, sections)
	return assemblePayload(in, sections, true)
}

func moduleHeaderLines(name string, result *domain.ModuleResult, present bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "=== %s ===\n", name)
	if !present {
		fmt.Fprintf(&b, "status: ok\n")
		return b.String()
	}
	fmt.Fprintf(&b, "status: %s\n", result.Status)
	if result.Status == domain.ModuleStatusError {
		errText := strings.TrimSpace(result.Error)
		if errText == "" {
			errText = "unknown error"
		}
		fmt.Fprintf(&b, "error: %s\n", errText)
	}
	return b.String()
}

func parseRawBlobs(raw json.RawMessage) map[string]string {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil
	}
	var blobs map[string]string
	if err := json.Unmarshal(trimmed, &blobs); err != nil {
		return map[string]string{"_raw": string(trimmed)}
	}
	if len(blobs) == 0 {
		return nil
	}
	return blobs
}

func assemblePayload(in analyze.Input, sections []moduleSection, truncated bool) string {
	var b strings.Builder
	if truncated {
		b.WriteString(truncationWarning)
	}
	fmt.Fprintf(&b, "hostname: %s\n", in.Report.Hostname)
	fmt.Fprintf(&b, "generated-at: %s\n", in.Report.GeneratedAt.Format("2006-01-02 15:04:05"))
	for _, section := range sections {
		b.WriteString("\n")
		b.WriteString(section.headerLines)
		if len(section.blobs) == 0 {
			continue
		}
		b.WriteString(formatBlobsJSON(section.blobs))
	}
	return b.String()
}

func formatBlobsJSON(blobs map[string]string) string {
	keys := make([]string, 0, len(blobs))
	for k := range blobs {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	b.WriteString("{\n")
	for i, key := range keys {
		value := blobs[key]
		encoded, err := json.Marshal(value)
		if err != nil {
			encoded = []byte(`""`)
		}
		fmt.Fprintf(&b, "  %q: %s", key, string(encoded))
		if i < len(keys)-1 {
			b.WriteByte(',')
		}
		b.WriteByte('\n')
	}
	b.WriteString("}\n")
	return b.String()
}

func truncateSections(in analyze.Input, sections []moduleSection) {
	for {
		payload := assemblePayload(in, sections, true)
		if utf8.RuneCountInString(payload) <= maxPayloadRunes {
			return
		}
		idx := heaviestModuleIndex(sections)
		if idx < 0 {
			return
		}
		if !truncateLargestBlob(&sections[idx]) {
			return
		}
	}
}

func heaviestModuleIndex(sections []moduleSection) int {
	best := -1
	bestWeight := 0
	for i, section := range sections {
		weight := moduleBlobWeight(section)
		if weight > bestWeight {
			bestWeight = weight
			best = i
		}
	}
	return best
}

func moduleBlobWeight(section moduleSection) int {
	total := 0
	for _, value := range section.blobs {
		total += utf8.RuneCountInString(value)
	}
	return total
}

func truncateLargestBlob(section *moduleSection) bool {
	if len(section.blobs) == 0 {
		return false
	}
	key := largestBlobKey(section.blobs)
	value := section.blobs[key]
	runes := []rune(value)
	if len(runes) <= 1 {
		delete(section.blobs, key)
		return true
	}
	cut := len(runes) / 2
	if cut < 1 {
		cut = 1
	}
	section.blobs[key] = string(runes[:cut]) + truncatedBlobSuffix
	return true
}

func largestBlobKey(blobs map[string]string) string {
	bestKey := ""
	bestSize := -1
	for key, value := range blobs {
		size := utf8.RuneCountInString(value)
		if size > bestSize {
			bestSize = size
			bestKey = key
		}
	}
	return bestKey
}
