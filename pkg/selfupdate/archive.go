package selfupdate

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"
)

// extractBinary copies the archive's single vigolium entry into dst, refusing
// archives with no such entry, more than one, or one larger than limit.
func extractBinary(archivePath, goos string, dst io.Writer, limit int64) error {
	name := BinaryName(goos)
	if goos == "windows" {
		return extractZip(archivePath, name, dst, limit)
	}
	return extractTarGz(archivePath, name, dst, limit)
}

func entryMatches(entry, name string) bool {
	return path.Base(strings.ReplaceAll(entry, "\\", "/")) == name
}

func extractTarGz(archivePath, name string, dst io.Writer, limit int64) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("archive: %w", err)
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	found := 0
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("archive: %w", err)
		}
		if !entryMatches(hdr.Name, name) {
			continue
		}
		if hdr.Typeflag != tar.TypeReg {
			return fmt.Errorf("archive: %s is not a regular file", hdr.Name)
		}
		found++
		if found > 1 {
			return fmt.Errorf("archive: more than one %s entry", name)
		}
		if hdr.Size > limit {
			return fmt.Errorf("archive: %s is %d bytes, over the %d byte limit", hdr.Name, hdr.Size, limit)
		}
		if err := copyCapped(dst, tr, limit, hdr.Name); err != nil {
			return err
		}
	}
	if found == 0 {
		return fmt.Errorf("archive: no %s entry", name)
	}
	return nil
}

func extractZip(archivePath, name string, dst io.Writer, limit int64) error {
	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		return fmt.Errorf("archive: %w", err)
	}
	defer func() { _ = zr.Close() }()
	var entry *zip.File
	for _, zf := range zr.File {
		if !entryMatches(zf.Name, name) {
			continue
		}
		if !zf.Mode().IsRegular() {
			return fmt.Errorf("archive: %s is not a regular file", zf.Name)
		}
		if entry != nil {
			return fmt.Errorf("archive: more than one %s entry", name)
		}
		entry = zf
	}
	if entry == nil {
		return fmt.Errorf("archive: no %s entry", name)
	}
	if entry.UncompressedSize64 > uint64(limit) {
		return fmt.Errorf("archive: %s is %d bytes, over the %d byte limit", entry.Name, entry.UncompressedSize64, limit)
	}
	rc, err := entry.Open()
	if err != nil {
		return fmt.Errorf("archive: %w", err)
	}
	defer func() { _ = rc.Close() }()
	return copyCapped(dst, rc, limit, entry.Name)
}

// copyCapped copies at most limit bytes and fails when the source has more: a
// header that understates the size must not get past the cap.
func copyCapped(dst io.Writer, src io.Reader, limit int64, name string) error {
	n, err := io.Copy(dst, io.LimitReader(src, limit+1))
	if err != nil {
		return fmt.Errorf("archive: extract %s: %w", name, err)
	}
	if n > limit {
		return fmt.Errorf("archive: %s exceeds the %d byte limit", name, limit)
	}
	return nil
}

// runVersionCheck runs `<path> version --json` and requires it to report want.
// A binary that does not start (wrong platform, truncated) or reports another
// version never replaces the working one.
func runVersionCheck(ctx context.Context, binPath, want string) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, binPath, "version", "--json")
	cmd.Env = append(os.Environ(), "VIGOLIUM_DISABLE_UPDATE_CHECK=1", "NO_COLOR=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 300 {
			msg = msg[:300] + "…"
		}
		return fmt.Errorf("downloaded binary failed to run `version --json`: %w %s", err, msg)
	}
	got, err := reportedVersion(out)
	if err != nil {
		return fmt.Errorf("downloaded binary: %w", err)
	}
	if normalize(got) != normalize(want) {
		return fmt.Errorf("downloaded binary reports version %s, expected %s", got, want)
	}
	return nil
}

// reportedVersion reads the version out of `version --json` output: either a
// bare object with "version" or an envelope with items[0].version.
func reportedVersion(out []byte) (string, error) {
	if i := bytes.IndexByte(out, '{'); i > 0 {
		out = out[i:]
	}
	var doc struct {
		Version string `json:"version"`
		Items   []struct {
			Version string `json:"version"`
		} `json:"items"`
	}
	if err := json.NewDecoder(bytes.NewReader(out)).Decode(&doc); err != nil {
		return "", fmt.Errorf("unreadable `version --json` output: %w", err)
	}
	if doc.Version != "" {
		return doc.Version, nil
	}
	if len(doc.Items) > 0 && doc.Items[0].Version != "" {
		return doc.Items[0].Version, nil
	}
	return "", errors.New("`version --json` output has no version")
}
