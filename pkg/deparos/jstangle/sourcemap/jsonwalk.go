package sourcemap

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf16"
	"unicode/utf8"
)

// A minimal in-place JSON walker. encoding/json can only hand back a value by
// decoding it (allocating every string) or by copying it into a RawMessage;
// json.Decoder buffers each top-level value whole. A 30 MiB map is mostly
// `sourcesContent`, so either path holds a second copy of exactly the bytes
// the budgets exist to skip. These helpers return sub-slices of the input
// instead, and the parser decodes only the values it keeps.

// maxJSONDepth bounds container nesting so a hostile document cannot exhaust
// the stack. A source map nests a handful of levels; indexed maps add a few.
const maxJSONDepth = 256

var errJSONSyntax = errors.New("invalid JSON")

// walkObject calls fn for each member of the JSON object in data, in document
// order, with the member's value as a sub-slice of data. data must hold exactly
// one object, optionally surrounded by whitespace.
func walkObject(data []byte, fn func(key string, value []byte) error) error {
	i := skipSpace(data, 0)
	if i >= len(data) || data[i] != '{' {
		return fmt.Errorf("%w: expected object", errJSONSyntax)
	}
	end, err := scanObject(data, i, 0, fn)
	if err != nil {
		return err
	}
	if skipSpace(data, end) != len(data) {
		return fmt.Errorf("%w: trailing data after object", errJSONSyntax)
	}
	return nil
}

// walkArray calls fn for each element of the JSON array in data.
func walkArray(data []byte, fn func(index int, value []byte) error) error {
	i := skipSpace(data, 0)
	if i >= len(data) || data[i] != '[' {
		return fmt.Errorf("%w: expected array", errJSONSyntax)
	}
	end, err := scanArray(data, i, 0, fn)
	if err != nil {
		return err
	}
	if skipSpace(data, end) != len(data) {
		return fmt.Errorf("%w: trailing data after array", errJSONSyntax)
	}
	return nil
}

func skipSpace(data []byte, i int) int {
	for i < len(data) {
		switch data[i] {
		case ' ', '\t', '\r', '\n':
			i++
		default:
			return i
		}
	}
	return i
}

// scanValue returns the index just past the JSON value starting at data[i].
func scanValue(data []byte, i, depth int) (int, error) {
	if i >= len(data) {
		return 0, fmt.Errorf("%w: unexpected end of input", errJSONSyntax)
	}
	switch c := data[i]; {
	case c == '"':
		return scanString(data, i)
	case c == '{':
		return scanObject(data, i, depth+1, nil)
	case c == '[':
		return scanArray(data, i, depth+1, nil)
	case c == 't':
		return scanLiteral(data, i, "true")
	case c == 'f':
		return scanLiteral(data, i, "false")
	case c == 'n':
		return scanLiteral(data, i, "null")
	case c == '-' || (c >= '0' && c <= '9'):
		j := i + 1
		for j < len(data) && isNumberByte(data[j]) {
			j++
		}
		return j, nil
	default:
		return 0, fmt.Errorf("%w: unexpected %q at offset %d", errJSONSyntax, c, i)
	}
}

func isNumberByte(c byte) bool {
	return (c >= '0' && c <= '9') || c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-'
}

func scanLiteral(data []byte, i int, literal string) (int, error) {
	if len(data)-i < len(literal) || string(data[i:i+len(literal)]) != literal {
		return 0, fmt.Errorf("%w: bad literal at offset %d", errJSONSyntax, i)
	}
	return i + len(literal), nil
}

// scanString returns the index just past the string token at data[i]. It
// jumps between quotes with IndexByte rather than stepping byte by byte: string
// tokens are nearly the whole of a large map. Control characters inside the
// token are not checked here; unquoteString rejects them in any value that is
// actually decoded.
func scanString(data []byte, i int) (int, error) {
	j := i + 1
	for {
		quote := bytes.IndexByte(data[j:], '"')
		if quote < 0 {
			return 0, fmt.Errorf("%w: unterminated string", errJSONSyntax)
		}
		end := j + quote
		backslashes := 0
		for k := end - 1; k > i && data[k] == '\\'; k-- {
			backslashes++
		}
		if backslashes%2 == 0 {
			return end + 1, nil
		}
		j = end + 1
	}
}

// decodedLowerBound is a cheap lower bound on the decoded length of a string
// token: every escape sequence starts with a backslash and shrinks the text by
// at most 5 bytes (a 6-byte \uXXXX to one byte).
func decodedLowerBound(token []byte) int {
	inner := len(token) - 2
	return max(0, inner-5*bytes.Count(token, []byte{'\\'}))
}

// unquoteString decodes a JSON string token into a fresh byte slice with the
// semantics of encoding/json: invalid UTF-8 and unpaired surrogates become
// U+FFFD. It replaces json.Unmarshal into a string, which validates the token
// a second time and costs an extra copy to turn the string back into bytes.
func unquoteString(token []byte) ([]byte, error) {
	if len(token) < 2 || token[0] != '"' || token[len(token)-1] != '"' {
		return nil, fmt.Errorf("%w: not a string", errJSONSyntax)
	}
	inner := token[1 : len(token)-1]
	out := make([]byte, 0, len(inner))
	for i := 0; i < len(inner); {
		c := inner[i]
		switch {
		case c < 0x20:
			return nil, fmt.Errorf("%w: control character in string", errJSONSyntax)
		case c == '\\':
			if i+1 >= len(inner) {
				return nil, fmt.Errorf("%w: truncated escape", errJSONSyntax)
			}
			switch inner[i+1] {
			case '"', '\\', '/':
				out = append(out, inner[i+1])
			case 'b':
				out = append(out, '\b')
			case 'f':
				out = append(out, '\f')
			case 'n':
				out = append(out, '\n')
			case 'r':
				out = append(out, '\r')
			case 't':
				out = append(out, '\t')
			case 'u':
				r, ok := hex4(inner, i+2)
				if !ok {
					return nil, fmt.Errorf("%w: bad \\u escape", errJSONSyntax)
				}
				i += 6
				if utf16.IsSurrogate(r) {
					if r2, ok := hex4(inner, i+2); ok && i+1 < len(inner) && inner[i] == '\\' && inner[i+1] == 'u' {
						if decoded := utf16.DecodeRune(r, r2); decoded != utf8.RuneError {
							out = utf8.AppendRune(out, decoded)
							i += 6
							continue
						}
					}
					r = utf8.RuneError
				}
				out = utf8.AppendRune(out, r)
				continue
			default:
				return nil, fmt.Errorf("%w: bad escape", errJSONSyntax)
			}
			i += 2
		case c < utf8.RuneSelf:
			out = append(out, c)
			i++
		default:
			r, size := utf8.DecodeRune(inner[i:])
			if r == utf8.RuneError && size == 1 {
				out = utf8.AppendRune(out, utf8.RuneError)
			} else {
				out = append(out, inner[i:i+size]...)
			}
			i += size
		}
	}
	return out, nil
}

func hex4(data []byte, i int) (rune, bool) {
	if i+4 > len(data) {
		return 0, false
	}
	var r rune
	for _, c := range data[i : i+4] {
		switch {
		case c >= '0' && c <= '9':
			c -= '0'
		case c >= 'a' && c <= 'f':
			c = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			c = c - 'A' + 10
		default:
			return 0, false
		}
		r = r<<4 | rune(c)
	}
	return r, true
}

func scanObject(data []byte, i, depth int, fn func(key string, value []byte) error) (int, error) {
	if depth > maxJSONDepth {
		return 0, fmt.Errorf("%w: nesting exceeds %d", errJSONSyntax, maxJSONDepth)
	}
	i = skipSpace(data, i+1)
	if i < len(data) && data[i] == '}' {
		return i + 1, nil
	}
	for {
		if i >= len(data) || data[i] != '"' {
			return 0, fmt.Errorf("%w: expected member name at offset %d", errJSONSyntax, i)
		}
		keyEnd, err := scanString(data, i)
		if err != nil {
			return 0, err
		}
		keyToken := data[i:keyEnd]
		i = skipSpace(data, keyEnd)
		if i >= len(data) || data[i] != ':' {
			return 0, fmt.Errorf("%w: expected ':' at offset %d", errJSONSyntax, i)
		}
		valueStart := skipSpace(data, i+1)
		valueEnd, err := scanValue(data, valueStart, depth)
		if err != nil {
			return 0, err
		}
		if fn != nil {
			key, err := decodeKey(keyToken)
			if err != nil {
				return 0, err
			}
			if err := fn(key, data[valueStart:valueEnd]); err != nil {
				return 0, err
			}
		}
		i = skipSpace(data, valueEnd)
		if i >= len(data) {
			return 0, fmt.Errorf("%w: unterminated object", errJSONSyntax)
		}
		switch data[i] {
		case ',':
			i = skipSpace(data, i+1)
		case '}':
			return i + 1, nil
		default:
			return 0, fmt.Errorf("%w: expected ',' or '}' at offset %d", errJSONSyntax, i)
		}
	}
}

func scanArray(data []byte, i, depth int, fn func(index int, value []byte) error) (int, error) {
	if depth > maxJSONDepth {
		return 0, fmt.Errorf("%w: nesting exceeds %d", errJSONSyntax, maxJSONDepth)
	}
	i = skipSpace(data, i+1)
	if i < len(data) && data[i] == ']' {
		return i + 1, nil
	}
	for index := 0; ; index++ {
		valueEnd, err := scanValue(data, i, depth)
		if err != nil {
			return 0, err
		}
		if fn != nil {
			if err := fn(index, data[i:valueEnd]); err != nil {
				return 0, err
			}
		}
		i = skipSpace(data, valueEnd)
		if i >= len(data) {
			return 0, fmt.Errorf("%w: unterminated array", errJSONSyntax)
		}
		switch data[i] {
		case ',':
			i = skipSpace(data, i+1)
		case ']':
			return i + 1, nil
		default:
			return 0, fmt.Errorf("%w: expected ',' or ']' at offset %d", errJSONSyntax, i)
		}
	}
}

// decodeKey decodes a member-name token, skipping the decoder for the common
// escape-free case.
func decodeKey(token []byte) (string, error) {
	inner := token[1 : len(token)-1]
	for _, c := range inner {
		if c == '\\' {
			var key string
			if err := json.Unmarshal(token, &key); err != nil {
				return "", err
			}
			return key, nil
		}
	}
	return string(inner), nil
}
