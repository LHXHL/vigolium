// Package olium is the root of the olium agent runtime. It wires providers,
// tools, and the engine into TUI / headless entrypoints.
package olium

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	oliumresources "github.com/vigolium/vigolium/internal/resources/olium"
	"github.com/vigolium/vigolium/pkg/olium/engine"
	"github.com/vigolium/vigolium/pkg/olium/provider"
	"github.com/vigolium/vigolium/pkg/olium/sessionlog"
	"github.com/vigolium/vigolium/pkg/olium/skill"
	"github.com/vigolium/vigolium/pkg/olium/tool"
	"github.com/vigolium/vigolium/pkg/olium/tui"
)

// LoadSkillsFor loads skills for a given mode. This is the single entry
// point every olium caller should use (TUI, headless, autopilot, swarm).
//
//   - includeUser=false for generic `vigolium agent olium` (chat/dev): only
//     .agents/skills, .claude/skills, and embedded built-ins.
//   - includeUser=true  for autopilot/swarm: adds ~/.vigolium/skills/ so
//     security-scan-specific skills are available without polluting chat.
//
// Warnings are returned but non-fatal — bad skills are skipped.
func LoadSkillsFor(includeUser bool) (*skill.Registry, []string) {
	reg, warnings, err := skill.LoadFromEmbed(oliumresources.SkillsFS, oliumresources.SkillsPrefix, includeUser)
	if err != nil {
		// LoadFromEmbed doesn't currently return errors on its own, but
		// defend against future changes — skills are non-essential.
		return nil, append(warnings, fmt.Sprintf("skill load: %v", err))
	}
	return reg, warnings
}

// DefaultModel is used when the user doesn't pass --model. Provider-specific
// defaults override this in resolveProvider.
const DefaultModel = DefaultOpenAIModel

// Per-vendor default models. resolveProvider picks from these and the
// `agent list` driver table renders them, so those two can never disagree.
// Flag help, usage examples and seed fixtures still quote ids literally —
// grep for the old id when bumping a generation.
const (
	// DefaultAnthropicModel is the default for every first-party Anthropic
	// transport (api key, OAuth, local CLI) and for Anthropic-on-Vertex,
	// which takes the same bare id.
	DefaultAnthropicModel = "claude-opus-5"
	// DefaultOpenAIModel is the default for the OpenAI transports
	// (api key, Responses, Codex OAuth).
	DefaultOpenAIModel = "gpt-5.5"
	// DefaultGoogleModel is the default for Gemini on Vertex.
	DefaultGoogleModel = "gemini-2.5-pro"
)

// SetDebug toggles provider-level tracing (full request payload + raw SSE
// events to stderr, credentials scrubbed) for every olium backend. The CLI
// wires the global --debug flag to this so the documented flag actually traces
// the in-process agent — the engine itself emits no zap logs, so plain --debug
// would otherwise show nothing for `vigolium ol`. Also honored via the
// VIGOLIUM_OLIUM_DEBUG env var at startup.
func SetDebug(on bool) { provider.SetDebug(on) }

// DefaultSystemPrompt is the baseline prompt when the user doesn't supply one.
const DefaultSystemPrompt = `You are olium, a security-focused coding agent running inside the vigolium scanner.
You have access to tools: bash, read_file, write_file, edit_file, ls, grep, glob, web_fetch.
Use them freely to explore code, run commands, and make changes. Be concise.`

// Options configures a `vigolium agent olium` run.
//
// Field naming spells the auth mechanism so it's obvious which fields apply
// to which provider:
//   - Provider="openai-codex-oauth" → OAuthCredPath
//   - Provider="anthropic-api-key"  → LLMAPIKey (or $ANTHROPIC_API_KEY)
//   - Provider="anthropic-oauth"    → OAuthToken  (or $ANTHROPIC_API_KEY); produced by `claude setup-token`
//   - Provider="openai-api-key"     → LLMAPIKey (or $OPENAI_API_KEY)
//   - Provider="openai-responses"   → LLMAPIKey (or $OPENAI_API_KEY); public
//     OpenAI Responses API (/v1/responses) instead of Chat Completions.
//   - Provider="anthropic-cli"      → ClaudeBinary
//   - Provider="anthropic-claude-sdk-bridge" → BridgeBinary (empty = embedded
//     vigolium-audit blob, then PATH); optional LLMAPIKey / OAuthToken are
//     forwarded, else the bridge uses ambient Claude Code subscription auth.
//   - Provider="anthropic-vertex"   → OAuthCredPath (SA JSON, or $GOOGLE_APPLICATION_CREDENTIALS),
//     plus GoogleCloudProject and GoogleCloudLocation; routes claude-* models.
//   - Provider="google-vertex"      → OAuthCredPath (SA JSON, or $GOOGLE_APPLICATION_CREDENTIALS),
//     plus GoogleCloudProject and GoogleCloudLocation; routes gemini-* models.
//   - Provider="openai-compatible"  → CustomBaseURL (required), CustomAPIKey
//     (optional), CustomModelID (fallback for Model), CustomExtraHeaders,
//     CustomExtraBody.
//     Covers Ollama / OpenRouter / LM Studio / vLLM / Together / Groq /
//     LocalAI / custom proxies.
//   - Provider="anthropic-compatible" → CustomBaseURL (required), CustomAPIKey
//     (optional), CustomModelID (fallback for Model), CustomExtraHeaders.
//     Speaks the Anthropic Messages API (/v1/messages) against a custom base
//     URL — a self-hosted gateway or Messages-compatible proxy.
type Options struct {
	// Provider selection. Empty = auto-detect (defaults to openai-codex-oauth).
	Provider string

	OAuthCredPath string // OAuth/SA credential file path (openai-codex-oauth, anthropic-vertex, google-vertex)
	OAuthToken    string // Anthropic OAuth bearer token (anthropic-oauth); explicit override, else falls back to $ANTHROPIC_API_KEY
	LLMAPIKey     string // API key for key-based providers; explicit override, else falls back to provider-specific env var
	Model         string
	SystemPrompt  string
	ClaudeBinary  string // path to `claude` executable for anthropic-cli provider
	BridgeBinary  string // path to `vigolium-audit` executable for anthropic-claude-sdk-bridge (empty = embedded blob, then PATH)

	// Vertex tuning (anthropic-vertex, google-vertex). ENV (GOOGLE_CLOUD_PROJECT
	// / GOOGLE_CLOUD_LOCATION) takes precedence at provider-construction time;
	// YAML/CLI values fill in when the env var is unset.
	GoogleCloudProject  string
	GoogleCloudLocation string

	// openai-compatible knobs (Ollama / OpenRouter / LM Studio / vLLM / etc.).
	// Mirrors agent.olium.custom_provider in YAML. CustomBaseURL is required
	// when Provider=="openai-compatible"; the rest are optional.
	CustomBaseURL      string
	CustomModelID      string
	CustomAPIKey       string
	CustomExtraHeaders map[string]string
	// CustomExtraBody is a generic JSON-body extension merged into every
	// outgoing request. Vigolium populates it from
	// custom_provider.EffectiveExtraBody() which combines the typed
	// provider_routing knob with the raw extra_body passthrough. Reserved
	// top-level keys (model, messages, tools, stream, stream_options) trigger
	// a request-time error.
	CustomExtraBody map[string]any

	// MaxTokens caps each response's output tokens (0 = provider default).
	// Mirrors agent.olium.max_tokens.
	MaxTokens int

	// ReasoningEffort is forwarded on every provider request and shown in
	// the TUI banner alongside the model id.
	// Plumbed from agent.olium.reasoning_effort. Display-only today; the
	// codex provider already defaults to "medium" when unset on the request.
	ReasoningEffort string

	// Version is the vigolium build version, displayed in the TUI banner
	// header (e.g. "Olium agent (v0.1.0-alpha)"). Optional — empty hides the
	// suffix.
	Version string

	// InitialPrompt seeds the TUI with a first message, auto-sent on
	// startup. Ignored in RunHeadless (which uses HeadlessOptions.Prompt).
	InitialPrompt string

	// SessionDir, when non-empty, is an existing directory into which the
	// run writes a Pi-style JSONL session transcript (transcript.jsonl) for
	// debugging. The CLI resolves it under agent.sessions_dir; library
	// callers may leave it empty to disable recording entirely. The runner
	// only writes into the directory — it does not create the per-run dir
	// (that's the CLI's job, mirroring the agentic-scan session layout).
	SessionDir string
}

// newSessionRecorder builds a Pi-style transcript recorder for an interactive
// or headless run when opts.SessionDir is set. It returns a true nil
// interface (never a typed nil) when recording is disabled or construction
// fails, so assigning the result to engine.Config.Recorder is always safe — a
// best-effort debug transcript must never block launching the agent.
func newSessionRecorder(opts Options, providerName, model string) engine.EventRecorder {
	if strings.TrimSpace(opts.SessionDir) == "" {
		return nil
	}
	cwd, _ := os.Getwd()
	rec, err := sessionlog.New(filepath.Join(opts.SessionDir, sessionlog.Filename), sessionlog.Meta{
		// Align the session id with the run dir name (matching autopilot) so
		// the transcript's id ties back to its on-disk location.
		SessionID:     filepath.Base(opts.SessionDir),
		Provider:      providerName,
		Model:         model,
		ThinkingLevel: opts.ReasoningEffort,
		Cwd:           cwd,
	})
	if err != nil {
		return nil
	}
	return rec
}

// RunTUI launches the interactive TUI.
func RunTUI(opts Options) error {
	prov, providerName, resolvedModel, err := resolveProvider(opts)
	if err != nil {
		return err
	}
	if opts.SystemPrompt == "" {
		opts.SystemPrompt = DefaultSystemPrompt
	}

	// yolo by default — nothing prompts; catastrophic patterns hard-reject
	// inside the bash tool itself.
	reg := tool.NewRegistry()
	tool.RegisterBuiltins(reg, nil)

	// Skills for interactive mode: project-local + embedded + user-scope
	// (~/.vigolium/skills, where the materialized + operator-authored skills
	// live). Surfaced so the operator can /skill:<name> them interactively.
	skills, _ := LoadSkillsFor(true)
	if skills != nil && skills.Len() > 0 {
		reg.Register(skill.NewLoadTool(skills, reg))
		fmt.Fprintf(os.Stderr, "Loaded %d skills (invoke with /skill:<name>)\n", skills.Len())
	}

	eng := engine.New(engine.Config{
		Provider:        prov,
		Tools:           reg,
		Skills:          skills,
		Model:           resolvedModel,
		System:          opts.SystemPrompt,
		ReasoningEffort: opts.ReasoningEffort,
		MaxTokens:       opts.MaxTokens,
		SessionID:       engine.SessionCacheKey(opts.SessionDir),
		Recorder:        newSessionRecorder(opts, providerName, resolvedModel),
	})
	// Flush + close the transcript when the interactive session ends. No-op
	// when no recorder was attached.
	defer func() { _ = eng.CloseRecorder() }()

	return tui.Run(tui.Config{
		Engine:        eng,
		ProviderName:  providerName,
		Model:         resolvedModel,
		Effort:        opts.ReasoningEffort,
		Version:       opts.Version,
		Skills:        skills,
		InitialPrompt: opts.InitialPrompt,
		SetupDocsURL:  SetupDocsURL,
	})
}

// buildHeadlessEngine is used by headless.go; shared so we only have one
// place that constructs the provider + registry + engine triple.
func buildHeadlessEngine(opts Options) (*engine.Engine, string, string, error) {
	prov, name, model, err := resolveProvider(opts)
	if err != nil {
		return nil, "", "", err
	}
	if opts.SystemPrompt == "" {
		opts.SystemPrompt = DefaultSystemPrompt
	}

	reg := tool.NewRegistry()
	tool.RegisterBuiltins(reg, nil)

	// Headless mode is used for smoke tests and scripted invocations —
	// same skill scope as the interactive TUI (no ~/.vigolium/skills).
	skills, _ := LoadSkillsFor(false)
	if skills != nil && skills.Len() > 0 {
		reg.Register(skill.NewLoadTool(skills, reg))
	}

	return engine.New(engine.Config{
		Provider:        prov,
		Tools:           reg,
		Skills:          skills,
		Model:           model,
		System:          opts.SystemPrompt,
		ReasoningEffort: opts.ReasoningEffort,
		MaxTokens:       opts.MaxTokens,
		SessionID:       engine.SessionCacheKey(opts.SessionDir),
		Recorder:        newSessionRecorder(opts, name, model),
	}), name, model, nil
}

// ResolveProvider picks the provider per options (or auto-detects) and
// resolves the model name (provider-default if the user didn't pass one).
// Exported so autopilot/swarm CLI paths can build a Provider from shared
// Options without duplicating selection logic.
func ResolveProvider(opts Options) (provider.Provider, string, string, error) {
	return resolveProvider(opts)
}

// resolveProvider is the internal implementation. Kept lowercase so
// existing callers (RunTUI, buildHeadlessEngine) continue to work.
// pickModel resolves a per-provider default: an unset model, or the
// cross-provider DefaultModel sentinel left by a caller that never chose one,
// becomes this provider's own default.
func pickModel(model, def string) string {
	if model == "" || model == DefaultModel {
		return def
	}
	return model
}

func resolveProvider(opts Options) (provider.Provider, string, string, error) {
	name := CanonicalProviderName(opts.Provider)
	if name == "" {
		name = autoDetectProvider(opts)
	}

	model := opts.Model
	switch name {
	case "openai-codex-oauth":
		return newOpenAICodexOAuthProvider(opts, pickModel(model, DefaultOpenAIModel))
	case "anthropic-api-key":
		return newAnthropicAPIKeyProvider(opts, pickModel(model, DefaultAnthropicModel))
	case "anthropic-oauth":
		return newAnthropicOAuthProvider(opts, pickModel(model, DefaultAnthropicModel))
	case "openai-api-key":
		return newOpenAIAPIKeyProvider(opts, pickModel(model, DefaultOpenAIModel))
	case "openai-responses":
		return newOpenAIResponsesProvider(opts, pickModel(model, DefaultOpenAIModel))
	case "anthropic-cli":
		return newAnthropicCLIProvider(opts, pickModel(model, DefaultAnthropicModel))
	case "anthropic-claude-sdk-bridge":
		// Empty model → let the bridge/Claude Code pick its own default (it
		// accepts short aliases like "opus"/"sonnet" or full ids). Only strip
		// the cross-provider DefaultModel sentinel so it isn't sent verbatim.
		if model == DefaultModel {
			model = ""
		}
		return newClaudeSDKBridgeProvider(opts, model)
	case "anthropic-vertex":
		return newAnthropicVertexProvider(opts, pickModel(model, DefaultAnthropicModel))
	case "google-vertex":
		return newGoogleVertexProvider(opts, pickModel(model, DefaultGoogleModel))
	case "openai-compatible":
		// No universal default — local models vary wildly. Fall back to
		// custom_provider.model_id when --model / agent.olium.model is empty.
		if model == "" || model == DefaultModel {
			model = opts.CustomModelID
		}
		return newOpenAICompatibleProvider(opts, model)
	case "anthropic-compatible":
		// No universal default — a gateway can front any Claude/other model.
		// Fall back to custom_provider.model_id when --model / agent.olium.model
		// is empty.
		if model == "" || model == DefaultModel {
			model = opts.CustomModelID
		}
		return newAnthropicCompatibleProvider(opts, model)
	default:
		return nil, "", "", fmt.Errorf("unknown provider %q (valid: %s)", name, ProviderNamesString(", "))
	}
}
