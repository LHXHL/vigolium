package curl

import (
	"strings"
)

// extractFromShellScript finds curl commands inside a bash script.
// Statements are split quote-aware (see splitStatements), so a multi-line
// quoted body and `$'...'` strings stay inside their command, and comments are
// skipped.
func extractFromShellScript(content string) []string {
	var commands []string
	for _, stmt := range splitStatements(content) {
		// In shell scripts, curl must be at the start of the statement to avoid
		// matching "echo curl" or similar
		if strings.HasPrefix(stmt, "curl ") {
			commands = append(commands, stmt)
		}
	}
	return commands
}

// extractFromMarkdown finds curl commands inside fenced code blocks in markdown.
func extractFromMarkdown(content string) []string {
	lines := strings.Split(content, "\n")
	var commands []string
	inCodeBlock := false

	var blockLines []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "```") {
			if inCodeBlock {
				// End of code block - process accumulated lines
				for _, stmt := range splitStatements(strings.Join(blockLines, "\n")) {
					if cmd := extractCurlFromLine(stmt); cmd != "" {
						commands = append(commands, cmd)
					}
				}
				blockLines = nil
				inCodeBlock = false
			} else {
				// Start of code block
				inCodeBlock = true
				blockLines = nil
			}
			continue
		}

		if inCodeBlock {
			blockLines = append(blockLines, line)
		}
	}

	return commands
}

// extractRawCommands treats content as a list of curl commands, each of which
// may span several lines (backslash continuations, or a quoted body that
// contains newlines).
func extractRawCommands(content string) []string {
	var commands []string
	for _, stmt := range splitStatements(content) {
		if strings.HasPrefix(stmt, "curl ") || stmt == "curl" {
			commands = append(commands, stmt)
		}
	}
	return commands
}

// splitStatements splits shell-like text into trimmed, non-empty statements.
//
// A statement ends at a newline that is outside every quote and not escaped
// by a trailing backslash, or at an unquoted `;` (followed by whitespace),
// `|`, `||` or `&&` (preceded by whitespace) — so `curl ... | jq .` and the
// ` ;` separators of Chrome's "Copy all as cURL" yield the curl command alone.
// A `#` that begins a word outside quotes starts a comment running to the end
// of the line. Line-based splitting broke a `-d '{\n "a": 1\n}'` body into
// three unparseable fragments and let an apostrophe in a comment swallow the
// file; this scanner tracks '...', "...", $'...' and backslash escapes.
//
// When a quote is still open at end of input, the statement it began cannot
// be recovered. Its first physical line is emitted on its own (parsing it then
// reports the unterminated quote) and scanning resumes on the next line, so
// one bad command does not swallow every command after it.
func splitStatements(content string) []string {
	var out []string
	for {
		stmts, rest, complete := scanStatements(content)
		out = append(out, stmts...)
		if complete {
			return out
		}
		line, after, found := strings.Cut(rest, "\n")
		if s := strings.TrimSpace(line); s != "" {
			out = append(out, s)
		}
		if !found {
			return out
		}
		content = after
	}
}

// scanStatements is one pass of splitStatements. It returns the completed
// statements and, when input ended inside a quote, complete=false with rest
// set to the text of the unterminated statement.
func scanStatements(content string) (stmts []string, rest string, complete bool) {
	var (
		cur       strings.Builder
		stmtStart int
		inSingle  bool
		inDouble  bool
		inANSI    bool
		escaped   bool
		wordStart = true
	)

	flush := func(next int) {
		if s := strings.TrimSpace(cur.String()); s != "" {
			stmts = append(stmts, s)
		}
		cur.Reset()
		stmtStart = next
		wordStart = true
	}

	for i := 0; i < len(content); i++ {
		ch := content[i]

		if escaped {
			escaped = false
			cur.WriteByte(ch)
			if ch == '\r' && i+1 < len(content) && content[i+1] == '\n' {
				i++
				cur.WriteByte('\n')
			}
			wordStart = false
			continue
		}

		switch {
		case inSingle:
			cur.WriteByte(ch)
			if ch == '\'' {
				inSingle = false
			}
			continue
		case inANSI:
			cur.WriteByte(ch)
			if ch == '\\' && i+1 < len(content) {
				i++
				cur.WriteByte(content[i])
			} else if ch == '\'' {
				inANSI = false
			}
			continue
		case inDouble:
			cur.WriteByte(ch)
			if ch == '\\' && i+1 < len(content) {
				i++
				cur.WriteByte(content[i])
			} else if ch == '"' {
				inDouble = false
			}
			continue
		}

		isSpace := ch == ' ' || ch == '\t' || ch == '\r'
		switch {
		case ch == '\n':
			flush(i + 1)
			continue
		case ch == '#' && wordStart:
			// Comment: skip to (not past) the end of the line.
			for i+1 < len(content) && content[i+1] != '\n' {
				i++
			}
			continue
		case ch == ';' && (i+1 == len(content) || isShellSpace(content[i+1])):
			flush(i + 1)
			continue
		case (ch == '|' || (ch == '&' && i+1 < len(content) && content[i+1] == '&')) && wordStart:
			if i+1 < len(content) && content[i+1] == ch {
				i++ // || or &&
			}
			flush(i + 1)
			continue
		case ch == '\\':
			escaped = true
		case ch == '$' && i+1 < len(content) && content[i+1] == '\'':
			inANSI = true
			cur.WriteByte(ch)
			i++
			ch = content[i]
		case ch == '\'':
			inSingle = true
		case ch == '"':
			inDouble = true
		}
		cur.WriteByte(ch)
		wordStart = isSpace
	}

	if inSingle || inDouble || inANSI {
		return stmts, content[stmtStart:], false
	}
	flush(len(content))
	return stmts, "", true
}

func isShellSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n'
}

// extractCurlFromLine extracts a curl command from a statement: everything
// from the first "curl " on (so a copied "$ curl ..." prompt is dropped).
func extractCurlFromLine(line string) string {
	idx := strings.Index(line, "curl ")
	if idx < 0 {
		return ""
	}

	cmd := strings.TrimSpace(line[idx:])
	if cmd == "" || cmd == "curl" {
		return ""
	}

	return cmd
}
