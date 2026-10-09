package curl

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/input/formats"
	"go.uber.org/zap"
)

// Options contains curl-specific parsing options.
type Options struct {
	// Variables maps variable names to values for ${KEY} and {{KEY}} substitution
	Variables map[string]string
}

// Format implements formats.Format for curl command files.
type Format struct {
	formatOpts formats.InputFormatOptions
	curlOpts   Options
}

// New creates a new curl Format parser.
func New() *Format {
	return &Format{}
}

var _ formats.Format = &Format{}

// Name returns the format name.
func (f *Format) Name() string {
	return "curl"
}

// SetOptions sets generic format options.
func (f *Format) SetOptions(options formats.InputFormatOptions) {
	f.formatOpts = options
}

// SetCurlOptions sets curl-specific options.
func (f *Format) SetCurlOptions(opts Options) {
	f.curlOpts = opts
}

// Parse reads a file containing curl commands and calls callback for each parsed request.
// Auto-detects format by extension: .sh → shell script, .md → markdown, otherwise raw curl-per-line.
func (f *Format) Parse(input string, callback formats.ParseReqRespCallback) error {
	data, err := os.ReadFile(input)
	if err != nil {
		return fmt.Errorf("failed to read curl file: %w", err)
	}

	content := string(data)

	// Apply variable substitution
	if len(f.curlOpts.Variables) > 0 {
		content = f.replaceVariables(content)
	}

	commands := extractCommands(input, content)

	for _, cmd := range commands {
		rr, err := ParseSingleCommand(cmd)
		if err != nil {
			// Warn, not Debug: a command that will not parse (an unknown flag,
			// an unterminated quote) is otherwise silently missing from the scan.
			zap.L().Warn("curl: skipping command",
				zap.String("cmd", truncate(cmd, 100)),
				zap.Error(err))
			continue
		}

		if !callback(rr) {
			return nil
		}
	}
	return nil
}

// Count returns the number of curl commands in the file.
func (f *Format) Count(input string) (int64, error) {
	data, err := os.ReadFile(input)
	if err != nil {
		return 0, err
	}

	commands := extractCommands(input, string(data))
	return int64(len(commands)), nil
}

// extractCommands picks the extractor by extension: .sh/.bash → shell script,
// .md/.markdown → fenced code blocks, otherwise a plain list of commands.
func extractCommands(input, content string) []string {
	switch {
	case strings.HasSuffix(input, ".sh") || strings.HasSuffix(input, ".bash"):
		return extractFromShellScript(content)
	case strings.HasSuffix(input, ".md") || strings.HasSuffix(input, ".markdown"):
		return extractFromMarkdown(content)
	default:
		return extractRawCommands(content)
	}
}

var (
	bashVarPattern     = regexp.MustCompile(`\$\{([^}]+)\}`)
	templateVarPattern = regexp.MustCompile(`\{\{([^}]+)\}\}`)
)

// replaceVariables substitutes ${KEY} and {{KEY}} with values from the variable map.
func (f *Format) replaceVariables(s string) string {
	// Replace ${KEY} patterns
	s = bashVarPattern.ReplaceAllStringFunc(s, func(match string) string {
		key := match[2 : len(match)-1] // strip ${ and }
		// Handle bash default syntax: ${VAR:-default}
		if varName, defaultVal, ok := strings.Cut(key, ":-"); ok {
			if val, found := f.curlOpts.Variables[varName]; found {
				return val
			}
			return defaultVal
		}
		if val, ok := f.curlOpts.Variables[key]; ok {
			return val
		}
		return match
	})

	// Replace {{KEY}} patterns
	s = templateVarPattern.ReplaceAllStringFunc(s, func(match string) string {
		key := match[2 : len(match)-2] // strip {{ and }}
		if val, ok := f.curlOpts.Variables[key]; ok {
			return val
		}
		return match
	})

	return s
}

// truncate returns the first n characters of s, appending "..." if truncated.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
