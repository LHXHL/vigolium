package queue

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"go.uber.org/zap"
)

// LegacyServerQueuePrefix names the per-PID queue directories older servers
// created under os.TempDir() and never removed.
const LegacyServerQueuePrefix = "vigolium-server-queue-"

// serverQueueLockName is the flock'ed lock file inside a server queue dir.
const serverQueueLockName = "LOCK"

// errDirLocked reports that another live process holds a queue dir's lock.
var errDirLocked = errors.New("queue directory locked by another process")

// ServerQueueDir is the durable queue directory a server owns for its
// lifetime. It is keyed by the database the server writes to, so a restart
// against the same database finds (and resumes) what the last run left queued,
// and two servers on different databases never share one.
type ServerQueueDir struct {
	// Path is the directory to hand to the disk queue.
	Path string
	// Fallback is true when the primary directory was locked by a live
	// process and this one is a PID-suffixed sibling.
	Fallback bool
	// Primary is the keyed directory, whether or not it was used.
	Primary string

	lock *os.File
}

// ServerQueueKey hashes a database identity into a directory name.
func ServerQueueKey(identity string) string {
	sum := sha256.Sum256([]byte(identity))
	return hex.EncodeToString(sum[:])[:16]
}

// OpenServerQueueDir creates (0700) and locks root/<key>. When another live
// process holds that lock it falls back to root/<key>-<pid>, which is never
// resumed by a later run and is removed on Release. With discard set, any
// segments already in the chosen directory are deleted before use.
func OpenServerQueueDir(root, identity string, discard bool) (*ServerQueueDir, error) {
	primary := filepath.Join(root, ServerQueueKey(identity))
	d := &ServerQueueDir{Path: primary, Primary: primary}
	lock, err := lockDir(primary)
	if errors.Is(err, errDirLocked) {
		d.Path = fmt.Sprintf("%s-%d", primary, os.Getpid())
		d.Fallback = true
		lock, err = lockDir(d.Path)
	}
	if err != nil {
		return nil, err
	}
	d.lock = lock
	if discard {
		n, err := DiscardSegments(d.Path)
		if err != nil {
			d.Release(false)
			return nil, err
		}
		if n > 0 {
			zap.L().Info("Discarded queued segments (--discard-queued)",
				zap.String("dir", d.Path), zap.Int("segments", n))
		}
	}
	return d, nil
}

// lockDir creates dir at 0700 and takes its lock.
func lockDir(dir string) (*os.File, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create queue dir %s: %w", dir, err)
	}
	return tryLockFile(filepath.Join(dir, serverQueueLockName))
}

// Release drops the lock. With empty set (the queue drained on a clean
// shutdown) the directory is removed; a fallback directory is removed either
// way, since no later run would ever look in it.
func (d *ServerQueueDir) Release(empty bool) {
	if d == nil {
		return
	}
	if d.lock != nil {
		unlockFile(d.lock)
		d.lock = nil
	}
	if empty || d.Fallback {
		if err := os.RemoveAll(d.Path); err != nil {
			zap.L().Debug("Remove server queue dir", zap.String("dir", d.Path), zap.Error(err))
		}
	}
}

// DiscardSegments deletes every segment directory under dir and reports how
// many it removed.
func DiscardSegments(dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "segment_") {
			continue
		}
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// SweepLegacyServerQueues removes tmpDir/vigolium-server-queue-<pid> dirs
// whose PID is no longer running, and PID-suffixed fallback dirs under root
// (root/<key>-<pid>) likewise. A directory whose owner is alive, or whose
// liveness cannot be determined, is left alone. Returns how many it removed.
func SweepLegacyServerQueues(tmpDir, root string) int {
	removed := 0
	sweep := func(dir string, pidOf func(name string) (int, bool)) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			pid, ok := pidOf(e.Name())
			if !ok || pid == os.Getpid() || !pidKnownDead(pid) {
				continue
			}
			if err := os.RemoveAll(filepath.Join(dir, e.Name())); err == nil {
				removed++
			}
		}
	}
	if tmpDir != "" {
		sweep(tmpDir, func(name string) (int, bool) {
			rest, ok := strings.CutPrefix(name, LegacyServerQueuePrefix)
			if !ok {
				return 0, false
			}
			pid, err := strconv.Atoi(rest)
			return pid, err == nil
		})
	}
	if root != "" {
		sweep(root, func(name string) (int, bool) {
			_, rest, ok := strings.Cut(name, "-")
			if !ok {
				return 0, false
			}
			pid, err := strconv.Atoi(rest)
			return pid, err == nil
		})
	}
	return removed
}
