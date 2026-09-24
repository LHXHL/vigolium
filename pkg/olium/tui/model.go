// Package tui implements the interactive Bubble Tea front-end for
// `vigolium agent olium`.
//
// It runs in inline/scrollback mode — NOT alt-screen. Completed messages
// are emitted to the terminal's normal output via tea.Printf so the user
// can scroll up, select, and copy like any other CLI. Only the prompt
// input box and the currently-streaming fragment are rendered as the
// live view; as soon as a fragment finalizes (a turn's text completes,
// a tool call finishes), it flushes into scrollback and the live view
// shrinks back to just the input.
package tui

import (
	"context"
	"errors"
	"os"
	"regexp"
	"strings"

	"charm.land/bubbles/v2/textarea"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/vigolium/vigolium/pkg/olium/engine"
	"github.com/vigolium/vigolium/pkg/olium/skill"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// Config configures the TUI.
type Config struct {
	Engine       *engine.Engine
	ProviderName string
	Model        string
	// Effort is the reasoning effort label (minimal|low|medium|high|xhigh|max)
	// shown next to the model id in the boot banner. Empty hides it.
	Effort string
	// Version is the vigolium build version, shown after "Olium agent" in
	// the boot banner. Empty hides the parenthetical.
	Version string
	// Skills is consulted when the user types `/skill:name args`. The
	// matching skill's body is expanded inline into the submitted prompt.
	// nil → /skill: commands are rejected with an error.
	Skills *skill.Registry
	// InitialPrompt, when non-empty, is auto-sent as the first message on
	// startup — same as if the user typed it and pressed enter.
	InitialPrompt string
	// SetupDocsURL is the provider-setup guide, appended under a run error
	// that looks credential- or endpoint-shaped. The TUI owns the whole
	// session, so an auth failure never returns to the CLI where the
	// equivalent hint is printed — this is the only place a user in an
	// interactive session sees it. Empty hides the pointer.
	SetupDocsURL string
	// quit is wired by Run() to the external context cancel passed via
	// tea.WithContext. When called, Bubble Tea's shutdown flips to "killed"
	// mode, which skips its 500 ms waitForReadLoop timeout on the TTY input
	// reader — otherwise ctrl+C takes up to that long to return.
	quit func()
}

type eventMsg engine.Event
type runClosedMsg struct{}
type sendMsg struct{ prompt string }

type turnState int

const (
	stateIdle turnState = iota
	stateStreaming
)

// --- Palette (xterm 256) ---
var (
	colorAccent    = lipgloss.Color("86") // cyan — brand, borders, hints
	colorAccentDim = lipgloss.Color("73")
	colorVigolium  = lipgloss.Color("46") // hi green — the assistant label
	colorUser      = lipgloss.Color("114")
	colorText      = lipgloss.Color("252")
	colorMuted     = lipgloss.Color("245")
	colorDim       = lipgloss.Color("240")
	colorWarn      = lipgloss.Color("215")
	colorErr       = lipgloss.Color("204")
	colorOK        = lipgloss.Color("114")
	// colorUserBg is the subtle "chat bubble" tint applied to every line of a
	// user prompt so it reads as a distinct block from the assistant's reply
	// (which stays on the default terminal background). 235 = #262626 — light
	// enough to lift off a black background, dim enough not to hurt on a dark
	// terminal theme. Bump to 236/237 for more contrast.
	colorUserBg = lipgloss.Color("235")
)

// userRail is the leading column glyph on every line of a user prompt block.
// Easy to swap — see the alternatives noted in renderUserBlock's docstring.
const userRail = "▶ "

var (
	styleUserLabel   = lipgloss.NewStyle().Bold(true).Foreground(colorUser)
	styleUserBody    = lipgloss.NewStyle().Foreground(colorText).Background(colorUserBg)
	styleBody        = lipgloss.NewStyle().Foreground(colorText)
	styleThinking    = lipgloss.NewStyle().Italic(true).Faint(true).Foreground(colorMuted)
	styleToolName    = lipgloss.NewStyle().Bold(true).Foreground(colorWarn)
	styleToolArgs    = lipgloss.NewStyle().Foreground(colorMuted)
	styleToolOK      = lipgloss.NewStyle().Foreground(colorOK)
	styleToolErr     = lipgloss.NewStyle().Foreground(colorErr)
	styleErr         = lipgloss.NewStyle().Bold(true).Foreground(colorErr)
	styleHint        = lipgloss.NewStyle().Foreground(colorDim)
	styleStatus      = lipgloss.NewStyle().Foreground(colorMuted)
	styleCaret       = lipgloss.NewStyle().Foreground(colorAccentDim)
	styleMDMarker    = lipgloss.NewStyle().Foreground(colorDim)
	styleInputBorder = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(colorDim).
				Padding(0, 1)

	// Markdown inline styles. These only add ANSI attributes — they never
	// rewrite characters — so stripping ANSI from renderProse output still
	// yields the original raw markdown source.
	styleMDH1        = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("10"))
	styleMDH2        = lipgloss.NewStyle().Bold(true).Foreground(colorAccent)
	styleMDH3        = lipgloss.NewStyle().Bold(true).Foreground(colorUser)
	styleMDHMark     = lipgloss.NewStyle().Faint(true).Foreground(colorAccentDim)
	styleMDBold      = lipgloss.NewStyle().Bold(true).Foreground(colorText)
	styleMDItalic    = lipgloss.NewStyle().Italic(true).Foreground(colorText)
	styleMDStrike    = lipgloss.NewStyle().Strikethrough(true).Foreground(colorMuted)
	styleMDCode      = lipgloss.NewStyle().Foreground(colorWarn)
	styleMDLinkText  = lipgloss.NewStyle().Underline(true).Foreground(colorAccent)
	styleMDLinkURL   = lipgloss.NewStyle().Faint(true).Foreground(colorAccentDim)
	styleMDLinkPunct = lipgloss.NewStyle().Foreground(colorDim)
	styleMDListMark  = lipgloss.NewStyle().Bold(true).Foreground(colorAccent)
	styleMDQuoteMark = lipgloss.NewStyle().Bold(true).Foreground(colorAccent)
	styleMDQuote     = lipgloss.NewStyle().Italic(true).Foreground(colorMuted)
)

var (
	reMDHeading  = regexp.MustCompile(`^(#{1,6})(\s+.*?)(\s*#*\s*)$`)
	reMDBullet   = regexp.MustCompile(`^(\s*)([-*+])(\s+)(.*)$`)
	reMDNumbered = regexp.MustCompile(`^(\s*)(\d+\.)(\s+)(.*)$`)
	reMDQuote    = regexp.MustCompile(`^(\s*>)(.*)$`)
	reMDLink     = regexp.MustCompile(`^\[([^\]\n]+)\]\(([^)\n]+)\)`)
)

// Model is the Bubble Tea model.
type Model struct {
	cfg Config

	input textarea.Model

	state   turnState
	eventCh <-chan engine.Event
	cancel  context.CancelFunc

	// Live-render state: only shown in View(), not yet committed to scrollback.
	//
	// Assistant text streams line-at-a-time into scrollback: every completed
	// `\n`-terminated line is flushed immediately via tea.Printf, so the user
	// watches the reply unfold instead of seeing only a one-line ticker.
	// streamPartial holds the bytes received since the last newline — the
	// still-in-progress line that hasn't been committed yet.
	//
	// Fenced code blocks are the one exception: chroma needs the whole body
	// to highlight, so when a ```lang opener arrives we flip inFence and
	// buffer every subsequent line in fenceBuf until the closing ``` line
	// arrives. At that point the whole fence flushes as a single highlighted
	// block. mdFenceNested tracks the nested-fence state machine used for
	// ```md / ```markdown outer fences (empty-lang closes the outer only when
	// not already inside a nested fence).
	streamPartial   string
	inFence         bool
	fenceLang       string
	fenceOpenLine   string
	fenceBuf        []string
	mdFenceNested   bool
	thinkingBuf     string
	thinkingFlushed bool
	liveTool        *liveTool // currently-executing tool, if any

	// Slash-command chooser state. slashOpen flips to true the moment the
	// input value starts with "/" (and contains no space/newline yet). The
	// chooser lists every available command — built-ins like /clear plus one
	// /skill:NAME entry per registered skill — filtered by what the user has
	// typed. Up/Down navigate, Tab autocompletes the highlighted entry into
	// the input, Esc dismisses, Enter still submits whatever's in the input.
	slashOpen     bool
	slashIdx      int
	slashFiltered []slashItem

	lastUsageLine string
	errMsg        string
	width         int
	height        int
}

type liveTool struct {
	id      string
	name    string
	args    map[string]any
	partial string
}

// slashItem is one row in the slash-command chooser. label is what the user
// sees (and what we prefix-match against), description is the hint shown to
// its right, and insertion is what gets written into the textarea on Tab —
// commands that take args end with a trailing space so the cursor lands
// where args belong.
type slashItem struct {
	label       string
	description string
	insertion   string
}

// buildSlashItems returns every command available to the chooser: the
// built-in /clear plus one /skill:NAME entry per registered skill, in the
// registry's stable order.
func buildSlashItems(reg *skill.Registry) []slashItem {
	items := []slashItem{
		{
			label:       "/clear",
			description: "reset the conversation and clear the screen",
			insertion:   "/clear",
		},
	}
	if reg == nil {
		return items
	}
	for _, s := range reg.List() {
		items = append(items, slashItem{
			label:       "/skill:" + s.Name,
			description: s.Description,
			insertion:   "/skill:" + s.Name + " ",
		})
	}
	return items
}

// filterSlashItems keeps every item whose label starts with the typed query.
// Prefix match (not fuzzy) so the results are predictable and the autocomplete
// always extends what the user is already typing.
func filterSlashItems(items []slashItem, query string) []slashItem {
	out := make([]slashItem, 0, len(items))
	for _, it := range items {
		if strings.HasPrefix(it.label, query) {
			out = append(out, it)
		}
	}
	return out
}

// New constructs a fresh Model.
func New(cfg Config) Model {
	ta := textarea.New()
	ta.Placeholder = "type your message…"
	ta.Prompt = styleCaret.Render("▶ ")
	ta.ShowLineNumbers = false
	ta.CharLimit = 0
	ta.SetHeight(1)

	// Neutralize placeholder highlight and cursor-line background that
	// some terminals render as a jarring selection block.
	// v2 hides the style fields behind Styles()/SetStyles() so the model
	// can keep its memoization cache in sync; mutate on a snapshot then
	// write back.
	placeholderStyle := lipgloss.NewStyle().Foreground(colorDim).Italic(true)
	taStyles := ta.Styles()
	taStyles.Focused.Placeholder = placeholderStyle
	taStyles.Blurred.Placeholder = placeholderStyle
	taStyles.Focused.CursorLine = lipgloss.NewStyle()
	taStyles.Blurred.CursorLine = lipgloss.NewStyle()
	ta.SetStyles(taStyles)

	ta.Focus()

	return Model{cfg: cfg, input: ta}
}

func (m Model) Init() tea.Cmd {
	cmds := []tea.Cmd{textarea.Blink, m.printBootHeader()}
	if p := strings.TrimSpace(m.cfg.InitialPrompt); p != "" {
		cmds = append(cmds, func() tea.Msg { return sendMsg{prompt: p} })
	}
	return tea.Batch(cmds...)
}

// mascotBodyStyle / mascotEyeStyle are the two colors the boot banner
// mascot is rendered with. Two colors keep the creature cohesive — the
// frame reads as one shape, the `(o)` / `<o>` eye pops as its accent.
var (
	mascotBodyStyle = lipgloss.NewStyle().Bold(true).Foreground(colorVigolium)
	mascotEyeStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("196"))
)

// styledMascot picks a random entry from the shared mascot pool and
// applies the 2-color scheme via lipgloss (so it composes with the rest
// of the banner's styling).
func styledMascot() string {
	return terminal.ColoredMascot(
		terminal.RandomMascot(),
		func(s string) string { return mascotBodyStyle.Render(s) },
		func(s string) string { return mascotEyeStyle.Render(s) },
	)
}

// homeShorten swaps the user's $HOME prefix back to "~" so the directory
// row stays readable in the banner.
func homeShorten(p string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return p
	}
	if p == home {
		return "~"
	}
	if strings.HasPrefix(p, home+string(os.PathSeparator)) {
		return "~" + p[len(home):]
	}
	return p
}

// printBootHeader emits a compact two-line welcome banner into scrollback:
//
//	<mascot>  Olium agent (v0.1.0-alpha)
//	escape interrupt · ctrl+c/ctrl+d clear/exit · / commands · ! bash
//
// The previous layout surfaced backend/model/cwd in the banner; those have
// moved to the persistent View() footer so they stay visible across turns
// instead of scrolling out of sight.
func (m Model) printBootHeader() tea.Cmd {
	prefix := styledMascot()

	title := lipgloss.NewStyle().Bold(true).Foreground(colorVigolium).Render("Olium agent")
	if v := strings.TrimSpace(m.cfg.Version); v != "" {
		title += " " + lipgloss.NewStyle().Faint(true).Foreground(colorMuted).Render("("+v+")")
	}
	headLine := prefix + "  " + title
	hint := styleHint.Render("escape interrupt · ctrl+c/ctrl+d clear/exit · / commands · ! bash")
	return tea.Printf("%s\n%s\n", headLine, hint)
}

// renderFooter builds the persistent status line drawn at the bottom of
// View(): `<dir> · <tokens> · <model> · <effort> (<backend>)`. Segments
// without data (tokens before the first turn, empty effort/backend) are
// dropped so the line stays compact.
func (m Model) renderFooter() string {
	cwd, err := os.Getwd()
	if err != nil {
		cwd = "?"
	}
	dir := homeShorten(cwd)

	modelSpec := strings.TrimSpace(m.cfg.Model)
	if e := strings.TrimSpace(m.cfg.Effort); e != "" {
		modelSpec = strings.TrimSpace(modelSpec + " · " + e)
	}
	if p := strings.TrimSpace(m.cfg.ProviderName); p != "" {
		if modelSpec == "" {
			modelSpec = p
		} else {
			modelSpec += " (" + p + ")"
		}
	}

	var parts []string
	parts = append(parts, styleStatus.Render(dir))
	if m.lastUsageLine != "" {
		parts = append(parts, styleStatus.Render(m.lastUsageLine))
	}
	if modelSpec != "" {
		parts = append(parts, styleStatus.Render(modelSpec))
	}
	return strings.Join(parts, styleHint.Render(" · "))
}

// maxInputLines caps how tall the input box can grow before it starts
// scrolling internally. 10 fits long multi-line prompts without taking
// over the screen.
const maxInputLines = 10

// resyncInputHeight grows / shrinks the textarea's internal viewport to
// match its current line count. Safe to call after any update — it only
// touches m.input.SetHeight, leaving cursor position alone.
func (m *Model) resyncInputHeight() {
	h := m.input.LineCount()
	if h < 1 {
		h = 1
	} else if h > maxInputLines {
		h = maxInputLines
	}
	m.input.SetHeight(h)
}

// resetInputViewport snaps the textarea's internal scroll offset back to
// the top by walking the cursor to the begin then to the end. It's needed
// after `splitLine` inserts a new row: the textarea's `repositionView`
// only scrolls to keep the cursor visible, so the viewport stays pinned
// to the new (empty) row and the row above it (with the user's typed
// text) becomes invisible. Walking via MoveToBegin first scrolls
// YOffset back to 0; MoveToEnd then puts the cursor where splitLine left
// it, but with the viewport now showing all rows.
func (m *Model) resetInputViewport() {
	m.input.MoveToBegin()
	m.input.MoveToEnd()
}

// refilterSlash re-evaluates whether the chooser should be open and which
// entries match what the user has typed. Open iff the input starts with "/"
// and contains no whitespace yet — once the user types past the command name
// (a space, or a newline), we close so the popup isn't in the way of args.
func (m *Model) refilterSlash() {
	val := m.input.Value()
	if !strings.HasPrefix(val, "/") || strings.ContainsAny(val, " \t\n") {
		m.slashOpen = false
		m.slashFiltered = nil
		m.slashIdx = 0
		return
	}
	m.slashFiltered = filterSlashItems(buildSlashItems(m.cfg.Skills), val)
	m.slashOpen = len(m.slashFiltered) > 0
	if m.slashIdx >= len(m.slashFiltered) {
		m.slashIdx = 0
	}
}

func (m *Model) startTurn(prompt string) (tea.Model, tea.Cmd) {
	m.resetStreamState()
	m.errMsg = ""
	m.state = stateStreaming

	// Flush user's prompt into scrollback right away so it looks anchored.
	// Prefix every line with the `▶` rail (in the user color) so multi-line
	// prompts read as one grouped block — no separate "you" label line.
	// Trailing "\n" gives the assistant reply breathing room — without it
	// the tinted user bubble butts directly against the first line of the
	// response and the two blocks visually smear together.
	userBlock := renderUserBlock(prompt, m.width) + "\n"

	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	ch := m.cfg.Engine.Run(ctx, prompt)
	m.eventCh = ch
	return m, tea.Sequence(m.printScrollback(userBlock), pumpEvents(ch))
}

// Run starts the TUI loop. Blocks until the user quits.
// Inline mode (NO alt-screen) so scrollback and mouse selection work.
//
// If stdin has been piped into the process (e.g., `echo hi | vigolium
// agent olium`), the caller is expected to have already consumed the pipe
// and populated cfg.InitialPrompt. In that case stdin is no longer a
// tty, so we reopen /dev/tty for Bubble Tea's key input — otherwise the
// program would see EOF and exit immediately.
func Run(cfg Config) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg.quit = cancel

	opts := []tea.ProgramOption{tea.WithContext(ctx)}
	if fi, err := os.Stdin.Stat(); err == nil && (fi.Mode()&os.ModeCharDevice) == 0 {
		if tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
			opts = append(opts, tea.WithInput(tty))
		}
	}
	p := tea.NewProgram(New(cfg), opts...)
	_, err := p.Run()
	// ErrProgramKilled is the expected outcome when ctrl+c cancels the
	// external context — not an error from the user's perspective.
	if errors.Is(err, tea.ErrProgramKilled) {
		return nil
	}
	return err
}
