package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// fileutil.HasStdin() is true for any stdin that is not a character device, so a
// pipe a parent process opened and never writes to looks exactly like a piped
// URL list. `vigolium run probe -t <url>` under a CI runner, an agent harness or
// a supervisor therefore stalled in readStdin() for the full three-minute
// --input-read-timeout before scanning the target it had been handed on the
// command line. These cases pin which invocations may drain stdin.
func TestResolveStdinInput(t *testing.T) {
	const noInput = ""

	cases := []struct {
		name        string
		stdinPiped  bool
		inputTyped  bool
		inputValue  string
		targets     int
		targetFiles int
		want        bool
	}{
		{
			name:       "no pipe, no targets: nothing to read",
			stdinPiped: false,
			want:       false,
		},
		{
			name:       "piped list, no targets: read it",
			stdinPiped: true,
			want:       true,
		},
		{
			name:       "regression: -t with an inherited pipe must not read stdin",
			stdinPiped: true,
			targets:    1,
			want:       false,
		},
		{
			name:        "regression: -T with an inherited pipe must not read stdin",
			stdinPiped:  true,
			targetFiles: 1,
			want:        false,
		},
		{
			name:       "typed -i - beats -t: stdin was asked for explicitly",
			stdinPiped: true,
			inputTyped: true,
			inputValue: "-",
			targets:    1,
			want:       true,
		},
		{
			// -i defaults to "-", so an untyped flag carrying that value is the
			// default case, not a request. Treating it as one reinstates the stall.
			name:       "untyped -i defaulting to - does not beat -t",
			stdinPiped: true,
			inputTyped: false,
			inputValue: "-",
			targets:    1,
			want:       false,
		},
		{
			name:       "-i <file> with a pipe: the file is the input",
			stdinPiped: true,
			inputTyped: true,
			inputValue: "./requests.txt",
			targets:    1,
			want:       false,
		},
		{
			// A typed -i <file> and no targets: the file is the input source, so
			// the stdin peek has nothing to contribute and must not block on it.
			name:       "-i <file> and no targets still skips stdin",
			stdinPiped: true,
			inputTyped: true,
			inputValue: "./requests.txt",
			want:       false,
		},
		{
			name:       "typed -i - with no pipe: nothing to read",
			stdinPiped: false,
			inputTyped: true,
			inputValue: "-",
			want:       false,
		},
		{
			name:       "no input flag at all with targets present",
			stdinPiped: true,
			inputValue: noInput,
			targets:    3,
			want:       false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveStdinInput(tc.stdinPiped, tc.inputTyped, tc.inputValue, tc.targets, tc.targetFiles)
			assert.Equal(t, tc.want, got)
		})
	}
}
