//go:build windows

package output

import "os/exec"

// setPDFProcessGroup is a no-op on Windows: there are no POSIX process
// groups, so a timeout falls back to exec.CommandContext's default cancel,
// which kills the browser process itself.
func setPDFProcessGroup(cmd *exec.Cmd) {}
