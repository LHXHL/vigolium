package modkit

import "testing"

// TestIndentedFrames is the regression guard for the defect these patterns
// shipped with: every repeated-frame pattern required the frames to be
// unindented, but Java, Node and .NET all indent theirs. The repetition broke at
// the second frame, {2,} never matched, and a real stack trace in a real
// response was never detected — a silent false negative in the one module whose
// entire job is detecting stack traces.
func TestStackTraceIndentedFrames(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "java tab-indented",
			body: "java.lang.NullPointerException\n" +
				"\tat com.example.Svc.run(Svc.java:42)\n" +
				"\tat com.example.Main.go(Main.java:7)\n",
		},
		{
			name: "java space-indented",
			body: "java.lang.IllegalStateException\n" +
				"    at com.example.Svc.run(Svc.java:42)\n" +
				"    at com.example.Main.go(Main.java:7)\n",
		},
		{
			name: "node space-indented",
			body: "TypeError: x is not a function\n" +
				"    at Object.<anonymous> (/app/server.js:15:3)\n" +
				"    at Module._compile (/app/loader.js:1:1)\n",
		},
		{
			name: "dotnet space-indented",
			body: "System.NullReferenceException: boom\n" +
				"   at App.Svc.Run() in C:/src/Svc.cs:line 42\n" +
				"   at App.Main() in C:/src/Main.cs:line 7\n",
		},
		{
			name: "ruby indented with from",
			body: "/app/controller.rb:42:in `index'\n" +
				"\tfrom /app/router.rb:7:in `dispatch'\n",
		},
		{
			name: "php trace",
			body: "#0 /app/index.php(42): Handler->run()\n" +
				"#1 /app/boot.php(7): Kernel->handle()\n",
		},
		{
			name: "python traceback",
			body: "Traceback (most recent call last):\n" +
				`  File "/app/views.py", line 42, in handler` + "\n",
		},
		{
			name: "go goroutine dump",
			body: "goroutine 1 [running]:\nmain.handler(0x0)\n\t/app/server.go:42 +0x1a3\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !BodyHasStackTrace(tt.body) {
				t.Errorf("BodyHasStackTrace() = false for a real %s stack trace; it must be detected", tt.name)
			}
		})
	}
}

// TestNoFalsePositives keeps the patterns from firing on prose or markup that
// merely mentions a language. The structure they require — repeated frames, a
// file path with a line number — is what separates a trace from an article.
func TestStackTraceNoFalsePositives(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"empty", ""},
		{"prose about java", "Our backend is written in Java and we handle exceptions carefully."},
		{"single java frame", "\tat com.example.Svc.run(Svc.java:42)\n"},
		{"html page", "<html><body><h1>Error</h1><p>Something went wrong.</p></body></html>"},
		{"json error", `{"error":"internal","trace":null}`},
		{"log line mentioning at", "2026-09-12 10:00:00 INFO request served at /api/users in 12ms\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if BodyHasStackTrace(tt.body) {
				t.Errorf("BodyHasStackTrace() = true for %q; this is not a stack trace", tt.name)
			}
		})
	}
}

// TestPatternsCarryMetadata guards the fields the finding-emitting consumer
// (verbose_error_stacktrace) reads off each pattern.
func TestStackTracePatternsCarryMetadata(t *testing.T) {
	if len(StackTracePatterns) == 0 {
		t.Fatal("no patterns registered")
	}
	for _, p := range StackTracePatterns {
		if p.Technology == "" {
			t.Error("pattern with empty Technology")
		}
		if p.Regexp == nil {
			t.Errorf("%s: nil Regexp", p.Technology)
		}
		if p.Severity == 0 {
			t.Errorf("%s: unset Severity", p.Technology)
		}
		if p.Confidence == 0 {
			t.Errorf("%s: unset Confidence", p.Technology)
		}
	}
}
