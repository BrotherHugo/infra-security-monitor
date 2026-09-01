package domain

import (
	"encoding/json"
	"time"
)

// ModuleName is a collector name from modules.enabled.
type ModuleName string

// ModuleStatus is the outcome of a single module collection.
type ModuleStatus string

const (
	ModuleStatusOK         ModuleStatus = "ok"
	ModuleStatusAttention  ModuleStatus = "attention"
	ModuleStatusError      ModuleStatus = "error"
)

// RunStatus is the outcome of a report cycle.
type RunStatus string

const (
	RunStatusOK       RunStatus = "ok"
	RunStatusDegraded RunStatus = "degraded"
	RunStatusFailed   RunStatus = "failed"
)

// ModuleResult is the Collect output for one module.
type ModuleResult struct {
	Name        ModuleName
	Status      ModuleStatus
	CollectedAt time.Time
	Raw         json.RawMessage // JSON object: named string blobs (raw module snapshot)
	SectionText string
	Error       string
}

// CollectionRun is one collect+report+send cycle attempt.
type CollectionRun struct {
	ID         int64
	StartedAt  time.Time
	FinishedAt *time.Time
	Hostname   string
	Status     RunStatus
}

// TextReport is the finished text for delivery channels.
type TextReport struct {
	GeneratedAt time.Time
	Hostname    string
	Body        string
}
