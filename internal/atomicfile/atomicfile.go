// Package atomicfile writes files atomically: content is streamed into a temp
// file in the destination directory and renamed into place only on success, so a
// failed or partial write never replaces or half-writes the destination.
package atomicfile

import (
	"bufio"
	"os"
	"path/filepath"
)

// Write atomically writes path's contents via write. It creates a temp file in
// path's directory, hands write a buffered writer, then flushes and renames the
// temp file over path on success. If write returns an error (or any I/O step
// fails) path is left untouched and the temp file is removed.
//
// write receives a *bufio.Writer so callers needing WriteByte/WriteString (e.g.
// incremental JSON array framing) can use them directly; it satisfies io.Writer
// for the common case.
func Write(path string, write func(w *bufio.Writer) error) error {
	return writeAtomic(path, 0, write)
}

// WriteBytes atomically writes data to path and makes it world-readable (0644,
// subject to umask), the mode every other artifact the CLI emits carries.
//
// Write leaves os.CreateTemp's 0600 in place, which is right for a temp file and
// wrong for a file the caller asked for by name.
func WriteBytes(path string, data []byte) error {
	return writeAtomic(path, 0o644, func(w *bufio.Writer) error {
		_, err := w.Write(data)
		return err
	})
}

// writeAtomic is the shared body. perm 0 leaves the temp file's mode alone.
func writeAtomic(path string, perm os.FileMode, write func(w *bufio.Writer) error) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()

	bw := bufio.NewWriter(tmp)
	if err := write(bw); err != nil {
		return err
	}
	if err := bw.Flush(); err != nil {
		return err
	}
	// Flushed to disk before the rename, so a crash cannot leave the destination
	// name pointing at a file whose contents never reached storage. Without it
	// "atomic" covers only the rename, not the bytes.
	if err := tmp.Sync(); err != nil {
		return err
	}
	if perm != 0 {
		if err := tmp.Chmod(perm); err != nil {
			return err
		}
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	committed = true
	return nil
}
