package modkit

import (
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/types/severity"
)

// This file is the shared catalog of language-runtime stack-trace signatures,
// and it lives beside sqlerrors.go for the same reason and in the same shape: a
// pattern table plus a body predicate, with two consumers that would otherwise
// each keep a copy. verbose_error_stacktrace reports a match as a finding;
// surface_scoring uses the boolean to tell a verbose error (the application
// answering) from a dead end.

// stackTraceBodyScanLimit caps how many leading body bytes the patterns scan.
// A runtime prints its trace at the top of the error page, and the patterns are
// unanchored full-DFA passes — running five of them over a multi-megabyte body
// to confirm what the first few KB already settle is the difference between a
// cheap check and a per-record cost on a 290k-record corpus. Mirrors
// edgeBlockBodyScanLimit.
const stackTraceBodyScanLimit = 16 << 10

// stackTraceHints are cheap literal screens. Every pattern below requires one of
// these substrings, so a body containing none cannot match and never enters the
// regex loop — which is the common case, since BodyHasStackTrace is asked about
// every error response in a scan and almost none carry a trace.
var stackTraceHints = []string{"at ", "Traceback", "goroutine ", ".rb:", ".php("}

// StackTracePattern is one language runtime's stack-trace signature, carrying
// the reporting metadata the finding-emitting module needs.
type StackTracePattern struct {
	Technology string
	Severity   severity.Severity
	Confidence severity.Confidence
	Regexp     *regexp.Regexp
}

// Patterns are the recognized stack-trace shapes. Each requires structure a
// prose mention of the language cannot produce — repeated frame lines, a file
// path with a line number — so an article about Java exceptions does not match.
//
// Every repeated frame group starts with [ \t]* because Java, Node and .NET all
// INDENT their frames ("\tat com.example..."). Without it the repetition broke
// at the second frame and {2,} never matched, so the patterns detected only the
// unindented form that no runtime actually emits — see TestStackTraceIndentedFrames.
var StackTracePatterns = []StackTracePattern{
	// Go stack traces: goroutine N [running]:
	// main.handler(...)
	//     /app/server.go:42 +0x1a3
	{
		Technology: "Go",
		Severity:   severity.Medium,
		Confidence: severity.Certain,
		Regexp:     regexp.MustCompile(`goroutine \d+ \[.*\]:\n.*\n\t(/[^\s]+\.go:\d+)`),
	},
	// Java stack traces: at com.example.Class.method(File.java:123)
	{
		Technology: "Java",
		Severity:   severity.Medium,
		Confidence: severity.Certain,
		Regexp:     regexp.MustCompile(`(?:[ \t]*at\s+[\w.$]+\([\w]+\.java:\d+\)[ \t]*\n){2,}`),
	},
	// Python stack traces: File "/app/views.py", line 42, in handler
	{
		Technology: "Python",
		Severity:   severity.Medium,
		Confidence: severity.Certain,
		Regexp:     regexp.MustCompile(`Traceback \(most recent call last\):[\s\S]*?File "([^"]+)", line \d+`),
	},
	// Node.js stack traces: at Object.<anonymous> (/app/server.js:15:3)
	{
		Technology: "Node.js",
		Severity:   severity.Medium,
		Confidence: severity.Firm,
		Regexp:     regexp.MustCompile(`(?:[ \t]*at\s+[\w.<>\[\] ]+\s+\((?:/[^\s)]+\.(?:js|ts|mjs|cjs):\d+:\d+)\)[ \t]*\n){2,}`),
	},
	// .NET/C# stack traces: at Namespace.Class.Method() in /app/File.cs:line 42
	{
		Technology: ".NET",
		Severity:   severity.Medium,
		Confidence: severity.Certain,
		Regexp:     regexp.MustCompile(`(?:[ \t]*at\s+[\w.]+\(.*?\)\s+in\s+[A-Za-z]?:?[/\\][\w./\\]+:\s*line\s+\d+[ \t]*\n){2,}`),
	},
	// Ruby stack traces: /app/controller.rb:42:in `index'
	{
		Technology: "Ruby",
		Severity:   severity.Medium,
		Confidence: severity.Certain,
		Regexp:     regexp.MustCompile(`(?:[ \t]*(?:from )?/[\w./]+\.rb:\d+:in ` + "`" + `[\w?!]+'[ \t]*\n){2,}`),
	},
	// PHP stack traces: #0 /app/index.php(42): Class->method()
	{
		Technology: "PHP",
		Severity:   severity.Medium,
		Confidence: severity.Certain,
		Regexp:     regexp.MustCompile(`(?:[ \t]*#\d+\s+/[\w./]+\.php\(\d+\):\s+[\w\\]+->[\w]+\(\)[ \t]*\n){2,}`),
	},
}

// BodyHasStackTrace reports whether body carries any recognized stack trace.
// It is the gate-only counterpart to iterating StackTracePatterns, mirroring
// BodyHasSQLError beside MatchSQLError.
//
// Two screens run before the regexes: the body is capped to its leading
// stackTraceBodyScanLimit bytes, and it must contain at least one cheap literal
// hint. Matching stops at the first pattern that hits, so a caller wanting only
// the yes/no answer never pays for the rest.
func BodyHasStackTrace(body string) bool {
	if body == "" {
		return false
	}
	if len(body) > stackTraceBodyScanLimit {
		body = body[:stackTraceBodyScanLimit]
	}
	hinted := false
	for _, h := range stackTraceHints {
		if strings.Contains(body, h) {
			hinted = true
			break
		}
	}
	if !hinted {
		return false
	}
	for i := range StackTracePatterns {
		if StackTracePatterns[i].Regexp.MatchString(body) {
			return true
		}
	}
	return false
}
