package analyze_test

import (
	"strings"
	"testing"

	"github.com/BrotherHugo/infra-security-monitor/internal/analyze"
)

func TestBuildSystemPrompt_default(t *testing.T) {
	got := analyze.BuildSystemPrompt("", "")
	if got != analyze.DefaultPrompt {
		t.Fatal("expected DefaultPrompt unchanged")
	}
	if !strings.Contains(got, "Custom rules:") {
		t.Fatal("DefaultPrompt must end with Custom rules: header")
	}
}

func TestDefaultPrompt_triageKnownFalsePositives(t *testing.T) {
	p := analyze.DefaultPrompt
	needles := []string{
		"systemd-networkd",
		"possible_false_positive",
		"SSH protocol v1",
		"lynis Suggestions",
		"PKGS-7388",
		"reboot now",
		"about 2-5",
	}
	for _, n := range needles {
		if !strings.Contains(p, n) {
			t.Errorf("DefaultPrompt missing %q", n)
		}
	}
}

func TestBuildSystemPrompt_customPromptReplacesDefault(t *testing.T) {
	custom := "Fully custom analyst prompt"
	got := analyze.BuildSystemPrompt(custom, "")
	if got != custom {
		t.Fatalf("prompt = %q, want %q", got, custom)
	}
}

func TestBuildSystemPrompt_customRulesAppended(t *testing.T) {
	rules := "Write the entire answer in Russian."
	got := analyze.BuildSystemPrompt("", rules)
	want := analyze.DefaultPrompt + "\n" + rules
	if got != want {
		t.Fatalf("prompt = %q, want %q", got, want)
	}
}

func TestBuildSystemPrompt_customPromptAndRules(t *testing.T) {
	custom := "Base prompt"
	rules := "Use German."
	got := analyze.BuildSystemPrompt(custom, rules)
	if got != custom+"\n"+rules {
		t.Fatalf("prompt = %q", got)
	}
}

func TestBuildSystemPrompt_trimsWhitespace(t *testing.T) {
	got := analyze.BuildSystemPrompt("  custom  ", "  rules  ")
	if got != "custom\nrules" {
		t.Fatalf("prompt = %q", got)
	}
}
