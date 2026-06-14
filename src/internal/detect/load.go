package detect

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// customPattern is one entry of a custom patterns JSON file.
type customPattern struct {
	Category string `json:"category"`
	Pattern  string `json:"pattern"`
}

// LoadCustomPatterns reads a JSON array of {category, pattern} from path and
// registers each as a detection rule. A blank path is a no-op.
func (e *Engine) LoadCustomPatterns(path string) error {
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var entries []customPattern
	if err := json.Unmarshal(data, &entries); err != nil {
		return fmt.Errorf("custom patterns %s: %w", path, err)
	}
	for _, p := range entries {
		if p.Category == "" || p.Pattern == "" {
			continue
		}
		if err := e.AddPattern(Category(p.Category), p.Pattern); err != nil {
			return fmt.Errorf("custom pattern %q: %w", p.Category, err)
		}
	}
	return nil
}

// LoadAllowlist reads one regex per line from path (blank lines and lines
// starting with # are ignored). A blank path is a no-op.
func (e *Engine) LoadAllowlist(path string) error {
	if path == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if err := e.AddAllowlistPattern(line); err != nil {
			return fmt.Errorf("allowlist %q: %w", line, err)
		}
	}
	return sc.Err()
}
