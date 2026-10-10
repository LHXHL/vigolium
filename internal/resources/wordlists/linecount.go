package wordlists

import (
	"bufio"
	"bytes"
	"sync"
)

// Logical names of the embedded discovery lists, by slot and tier.
const (
	NameShortFile = "file-short.txt"
	NameLongFile  = "file-long.txt"
	NameLargeFile = "file-large.txt"
	NameShortDir  = "dir-short.txt"
	NameLongDir   = "dir-long.txt"
	NameLargeDir  = "dir-large.txt"
	NameFuzz      = "fuzz.txt"
)

// ByName returns the materialized path of the embedded list with logical name
// name, or "" when it is not one of the discovery defaults.
func (p DefaultPaths) ByName(name string) string {
	switch name {
	case NameShortFile:
		return p.ShortFile
	case NameLongFile:
		return p.LongFile
	case NameLargeFile:
		return p.LargeFile
	case NameShortDir:
		return p.ShortDir
	case NameLongDir:
		return p.LongDir
	case NameLargeDir:
		return p.LargeDir
	case NameFuzz:
		return p.Fuzz
	}
	return ""
}

var lineCounts sync.Map // logical name → int64

// EmbeddedLineCount returns the number of words (non-blank lines) in the
// embedded wordlist with logical name name, read straight from the embed FS —
// nothing is written to disk, which is what lets a dry run size discovery
// without materializing the lists. Counted once per name per process.
func EmbeddedLineCount(name string) (int64, bool) {
	if v, ok := lineCounts.Load(name); ok {
		return v.(int64), true
	}
	data, err := ReadList(name)
	if err != nil {
		return 0, false
	}
	n := CountWords(data)
	lineCounts.Store(name, n)
	return n, true
}

// CountWords counts the non-blank lines of a wordlist.
func CountWords(data []byte) int64 {
	var n int64
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		if len(bytes.TrimSpace(sc.Bytes())) > 0 {
			n++
		}
	}
	return n
}
