package notify

import (
	"fmt"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/utils/textutil"
)

// SanitizeFilename replaces invalid filename characters with underscores.
func SanitizeFilename(name string) string {
	replacer := strings.NewReplacer(
		"/", "_", "\\", "_", ":", "_", "*", "_",
		"?", "_", "\"", "_", "<", "_", ">", "_", "|", "_",
	)
	return replacer.Replace(name)
}

// GenerateFilename creates a filename for attachments.
// Format: {moduleID}_{host}_{timestamp}.{ext}
func GenerateFilename(moduleID, host, ext string) string {
	return fmt.Sprintf("%s_%s_%d.%s",
		SanitizeFilename(moduleID),
		SanitizeFilename(host),
		time.Now().UnixNano(),
		ext,
	)
}

// Truncate truncates a string to maxLen bytes with ellipsis "...", never
// splitting a UTF-8 sequence (chat APIs reject invalid UTF-8).
func Truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return textutil.TruncateUTF8Ellipsis(s, maxLen, "...")
}

// TruncateWithIndicator truncates a string and adds "[see attachment]",
// never splitting a UTF-8 sequence.
func TruncateWithIndicator(s string, maxLen int) string {
	indicator := " [see attachment]"
	if len(s) <= maxLen {
		return s
	}
	cutLen := maxLen - len(indicator)
	if cutLen <= 0 {
		return indicator
	}
	return textutil.TruncateUTF8(s, cutLen) + indicator
}
