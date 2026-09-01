package execcmd

import "context"

// Runner runs external OS commands; replaced with a fake in tests.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (stdout string, stderr string, err error)
}
