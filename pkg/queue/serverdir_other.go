//go:build !unix

package queue

import "os"

// Without flock the lock file is only opened: two servers on the same
// database share the directory, as every server did before the lock existed.
func tryLockFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
}

func unlockFile(f *os.File) { _ = f.Close() }

// pidKnownDead cannot probe liveness here, so it never claims a PID is dead
// and the legacy sweep leaves everything alone.
func pidKnownDead(int) bool { return false }
