package config

import (
	"fmt"
	"strings"
)

// Notification provider identifiers used by NotifyConfig.Provider to select
// which channel is active. An empty value means "all configured providers
// fire" (the legacy behavior — telegram + discord both fire per-finding).
const (
	NotifyProviderWebhook  = "webhook"
	NotifyProviderTelegram = "telegram"
	NotifyProviderDiscord  = "discord"
)

// NotifyConfig holds notification configuration
type NotifyConfig struct {
	Enabled    bool     `yaml:"enabled,omitempty"`
	Severities []string `yaml:"severities,omitempty"`

	// Provider selects which single channel is active when set.
	// Valid values: "webhook", "telegram", "discord". Empty means "any
	// configured provider fires" (backward-compatible default).
	Provider string `yaml:"provider,omitempty"`

	Telegram TelegramConfig `yaml:"telegram,omitempty"`
	Discord  DiscordConfig  `yaml:"discord,omitempty"`
	Webhook  WebhookConfig  `yaml:"webhook,omitempty"`
}

// TelegramConfig holds Telegram notification settings
type TelegramConfig struct {
	BotToken string `yaml:"bot_token,omitempty"`
	ChatID   string `yaml:"chat_id,omitempty"`
}

// DiscordConfig holds Discord notification settings
type DiscordConfig struct {
	WebhookURL string `yaml:"webhook_url,omitempty"`
}

// WebhookConfig configures the per-project scan-completion webhook. It fires
// one POST per scan when the scan reaches a terminal state (completed, failed
// or cancelled), regardless of severity.
type WebhookConfig struct {
	URL           string `yaml:"url,omitempty"`
	Authorization string `yaml:"authorization,omitempty"`
	TimeoutSec    int    `yaml:"timeout_sec,omitempty"`
	// Events limits which terminal outcomes POST: any of "completed",
	// "failed", "cancelled" (the "scan." prefix is accepted too). Empty means
	// DefaultWebhookEvents, i.e. every outcome.
	Events []string `yaml:"events,omitempty"`
}

// Webhook outcome names accepted in notify.webhook.events. Each one is the
// suffix of the payload's `event` value (scan.completed, scan.failed,
// scan.cancelled).
const (
	WebhookEventCompleted = "completed"
	WebhookEventFailed    = "failed"
	WebhookEventCancelled = "cancelled"
)

// DefaultWebhookEvents is what an unset notify.webhook.events means.
var DefaultWebhookEvents = []string{WebhookEventCompleted, WebhookEventFailed, WebhookEventCancelled}

// normalizeWebhookEvent folds "scan.completed" / " Completed " to "completed".
func normalizeWebhookEvent(e string) string {
	return strings.TrimPrefix(strings.ToLower(strings.TrimSpace(e)), "scan.")
}

// AllowsEvent reports whether a payload whose `event` is event (for example
// "scan.failed") should be posted under notify.webhook.events.
func (w *WebhookConfig) AllowsEvent(event string) bool {
	if w == nil || len(w.Events) == 0 {
		return true
	}
	want := normalizeWebhookEvent(event)
	for _, e := range w.Events {
		if n := normalizeWebhookEvent(e); n == want || n == "all" || n == "*" {
			return true
		}
	}
	return false
}

// Validate rejects an events entry that names no outcome, which would
// otherwise silently filter that outcome's POSTs away.
func (w *WebhookConfig) Validate() error {
	if w == nil {
		return nil
	}
	for _, e := range w.Events {
		switch normalizeWebhookEvent(e) {
		case WebhookEventCompleted, WebhookEventFailed, WebhookEventCancelled, "all", "*":
		default:
			return fmt.Errorf("notify.webhook.events: unknown event %q (valid: %s)", e, strings.Join(DefaultWebhookEvents, ", "))
		}
	}
	return nil
}

// EffectiveTimeout returns the configured timeout in seconds, falling back to
// 10s when unset or non-positive.
func (w *WebhookConfig) EffectiveTimeout() int {
	if w == nil || w.TimeoutSec <= 0 {
		return 10
	}
	return w.TimeoutSec
}

// IsConfigured reports whether the webhook has the minimum config to fire
// (a non-empty URL). Provider gating is handled at the NotifyConfig layer.
func (w *WebhookConfig) IsConfigured() bool {
	return w != nil && strings.TrimSpace(w.URL) != ""
}

// IsConfigured reports whether telegram has both bot_token and chat_id set.
func (t *TelegramConfig) IsConfigured() bool {
	return t != nil && strings.TrimSpace(t.BotToken) != "" && strings.TrimSpace(t.ChatID) != ""
}

// IsConfigured reports whether discord has a webhook_url set.
func (d *DiscordConfig) IsConfigured() bool {
	return d != nil && strings.TrimSpace(d.WebhookURL) != ""
}

// IsProviderActive reports whether the given provider is allowed to fire
// given the master switch and the Provider selector.
//
// Rules:
//   - notify.enabled=false → nothing fires.
//   - notify.provider="" → all providers may fire (backward-compatible default).
//   - notify.provider=<X> → only X is allowed.
//
// This routing check does NOT validate per-channel config (URLs, tokens) —
// the caller pairs it with the channel's own IsConfigured() when needed.
// Telegram and discord backends honor env-var fallbacks (TELEGRAM_BOT_TOKEN,
// DISCORD_WEBHOOK_URL), so the runner gates on provider routing only and
// lets the per-backend constructors validate inputs.
func (n *NotifyConfig) IsProviderActive(provider string) bool {
	if n == nil || !n.Enabled {
		return false
	}
	sel := strings.ToLower(strings.TrimSpace(n.Provider))
	if sel == "" {
		return true
	}
	return sel == strings.ToLower(provider)
}

// IsWebhookActive reports whether the webhook should fire for this run.
// Combines provider routing with WebhookConfig.IsConfigured(); the webhook
// has no env-var fallback, so URL must be set in YAML.
func (n *NotifyConfig) IsWebhookActive() bool {
	return n.IsProviderActive(NotifyProviderWebhook) && n.Webhook.IsConfigured()
}

// DefaultNotifyConfig returns default notification configuration (disabled)
func DefaultNotifyConfig() *NotifyConfig {
	return &NotifyConfig{
		Enabled:    false,
		Severities: []string{"high", "critical", "medium"},
	}
}
