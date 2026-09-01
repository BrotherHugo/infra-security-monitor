package execcmd

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
)

// Exec is the production Runner implementation via os/exec.
type Exec struct{}

// Run executes a command respecting context cancellation.
func (Exec) Run(ctx context.Context, name string, args ...string) (string, string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return stdout.String(), stderr.String(), fmt.Errorf("exec %s %v: %w", name, args, err)
	}
	return stdout.String(), stderr.String(), nil
}
