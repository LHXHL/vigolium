//go:build !windows

package output

import (
	"os/exec"
	"syscall"
)

// setPDFProcessGroup starts Chrome as the leader of a new process group and
// makes context cancellation kill the whole group, so renderer, GPU and
// zygote children die with the browser instead of outliving a timed-out export.
func setPDFProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		// Negative pid targets the process group led by Chrome.
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
			return cmd.Process.Kill()
		}
		return nil
	}
}
