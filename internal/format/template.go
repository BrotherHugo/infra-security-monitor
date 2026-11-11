package format

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"
)

//go:embed default.tmpl
var defaultTemplateSrc string

var defaultRenderer *Renderer

func init() {
	renderer, err := Parse(defaultTemplateSrc)
	if err != nil {
		panic(fmt.Sprintf("built-in report template: %v", err))
	}
	defaultRenderer = renderer
}

// Renderer executes a report template.
type Renderer struct {
	tmpl *template.Template
}

// DefaultRenderer returns the built-in template (named module fields).
func DefaultRenderer() *Renderer {
	return defaultRenderer
}

// Parse compiles a template from source.
func Parse(src string) (*Renderer, error) {
	tmpl, err := template.New("report").Funcs(templateFuncs).Parse(src)
	if err != nil {
		return nil, err
	}
	return &Renderer{tmpl: tmpl}, nil
}

// Load reads a template file. An empty path returns the built-in template.
// Relative paths are resolved from baseDir (the config file's directory).
func Load(path, baseDir string) (*Renderer, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return defaultRenderer, nil
	}

	full := path
	if !filepath.IsAbs(path) {
		if strings.TrimSpace(baseDir) == "" {
			return nil, fmt.Errorf("template %q is relative and config directory is empty", path)
		}
		full = filepath.Join(baseDir, path)
	}

	data, err := os.ReadFile(full)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", full, err)
	}
	renderer, err := Parse(string(data))
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", full, err)
	}
	return renderer, nil
}

var templateFuncs = template.FuncMap{
	"join": strings.Join,
}
