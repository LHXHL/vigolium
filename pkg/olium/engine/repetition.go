package engine

import (
	"strings"
	"unicode"
)

// Degenerate-repetition guard.
//
// Small open-weight models (served through Ollama, llama.cpp, vLLM, often
// behind Open WebUI) sometimes fall into a loop, repeating one or two short
// lines ("Wait, I'll call them.\nActually, I'll call them.\n") until the
// server's output ceiling. The OpenAI-compatible transports send no
// max_tokens, and Ollama's default num_predict is unlimited, so one such
// turn can run for many minutes, flood the transcript and every UI consumer
// with the same line, and then go back into history to poison the next turn.
// The guard notices the loop in the streamed text and ends the turn early.

const (
	// repetitionWindow is how much of the text tail is tested for a loop.
	repetitionWindow = 2048
	// repetitionMaxPeriod is the longest repeating unit recognized. The
	// window must hold at least repetitionMinRepeats copies of it.
	repetitionMaxPeriod = repetitionWindow / repetitionMinRepeats
	// repetitionMinRepeats is how many back-to-back copies of a unit count as
	// a loop. Legitimate output (tables, lists) varies inside every row, so
	// it never matches byte-for-byte over a whole 2 KiB window.
	repetitionMinRepeats = 8
	// repetitionMinPeriod rejects very short units; degenerateRepetition also
	// rejects letterless ones (divider rules, box drawing, padding).
	repetitionMinPeriod = 3
	// repetitionCheckEvery spaces the checks out so a long turn is not
	// rescanned on every delta.
	repetitionCheckEvery = 256
)

// repetitionGuard watches one stream of text (answer or reasoning) for a
// degenerate loop. It keeps only a bounded tail of what it has seen, so a
// long turn costs no more memory than a short one.
type repetitionGuard struct {
	tail       []byte
	sinceCheck int
}

// feed records a delta and reports whether the stream now ends in a loop,
// with the length of the repeating unit.
func (g *repetitionGuard) feed(delta string) (period int, looping bool) {
	g.tail = append(g.tail, delta...)
	if len(g.tail) > 2*repetitionWindow {
		g.tail = append(g.tail[:0], g.tail[len(g.tail)-repetitionWindow:]...)
	}
	g.sinceCheck += len(delta)
	if g.sinceCheck < repetitionCheckEvery {
		return 0, false
	}
	g.sinceCheck = 0
	return degenerateRepetition(string(g.tail))
}

// degenerateRepetition reports whether s ends in at least
// repetitionMinRepeats exact copies of one unit, and returns the unit's
// length. The first (shortest) period found decides: every longer period of
// the window is a multiple of it (Fine-Wilf), so a letterless shortest unit
// means the whole window is letterless filler.
func degenerateRepetition(s string) (int, bool) {
	if len(s) < repetitionWindow {
		return 0, false
	}
	w := s[len(s)-repetitionWindow:]
	for p := repetitionMinPeriod; p <= repetitionMaxPeriod; p++ {
		periodic := true
		for i := p; i < len(w); i++ {
			if w[i] != w[i-p] {
				periodic = false
				break
			}
		}
		if periodic {
			// A letterless unit is a divider or filler, which models emit
			// on purpose.
			return p, strings.ContainsFunc(w[:p], unicode.IsLetter)
		}
	}
	return 0, false
}

// trimRepetition cuts a looping tail back to one copy of the repeating unit
// plus a marker, so history keeps what the model said before the loop without
// feeding the loop back into the next request.
func trimRepetition(s string, period int) string {
	if period <= 0 || len(s) < period {
		return s
	}
	// Walk back while the text keeps matching itself one period earlier;
	// start is then the beginning of the first copy.
	start := len(s) - period
	for start-period >= 0 && s[start-period:start] == s[start:start+period] {
		start -= period
	}
	return s[:start+period] + "\n[output cut: the model was repeating itself]"
}
