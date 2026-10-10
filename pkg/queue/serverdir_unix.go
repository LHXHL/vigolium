//go:build unix

package queue

import (
	"errors"
	"os"
	"syscall"

	"github.com/vigolium/vigolium/pkg/procutil"
)

// tryLockFile opens path (0600) and takes an exclusive, non-blocking flock.
// The lock belongs to the open file description, so it is released when the
// file is closed or the process dies — including on SIGKILL.
func tryLockFile(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, errDirLocked
		}
		return nil, err
	}
	return f, nil
}

func unlockFile(f *os.File) {
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	_ = f.Close()
}

// pidKnownDead reports whether pid definitely names no running process
// (procutil counts one that exists under another user as alive).
func pidKnownDead(pid int) bool {
	return pid > 0 && !procutil.IsProcessAlive(pid)
}
