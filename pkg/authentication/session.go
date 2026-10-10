package authentication

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/utils/yamlschema"
)

// Role identifies how a session is used during scanning.
type Role string

const (
	// RolePrimary drives discovery and spidering — the "owner" of the resources.
	RolePrimary Role = "primary"
	// RoleCompare is replayed during audit phase for cross-session comparison.
	RoleCompare Role = "compare"
)

// ExtractSource specifies where to extract authentication tokens from a login response.
type ExtractSource string

const (
	ExtractCookie ExtractSource = "cookie" // Extract from Set-Cookie header
	ExtractJSON   ExtractSource = "json"   // Extract from JSON response body
	ExtractHeader ExtractSource = "header" // Extract from response header
	ExtractRegex  ExtractSource = "regex"  // Extract from response body via regex
)

// LoginType is a shorthand preset that auto-expands into extract rules.
type LoginType string

const (
	LoginTypeBearer LoginType = "bearer" // JSON body → Authorization: Bearer {value}
	LoginTypeCookie LoginType = "cookie" // Capture all Set-Cookie headers
	// LoginTypeOAuth2ClientCredentials fetches an access token from token_url
	// with the client_credentials grant (oauth.go).
	LoginTypeOAuth2ClientCredentials LoginType = "oauth2_client_credentials"
	// LoginTypeOAuth2RefreshToken trades refresh_token for an access token at
	// token_url (oauth.go).
	LoginTypeOAuth2RefreshToken LoginType = "oauth2_refresh_token"
)

// IsOAuth2 reports whether t is one of the OAuth2 token-endpoint types, which
// take token_url/client_id/... instead of url/method/body/extract.
func (t LoginType) IsOAuth2() bool {
	return t == LoginTypeOAuth2ClientCredentials || t == LoginTypeOAuth2RefreshToken
}

// OAuth2 client authentication styles (login.auth_style).
const (
	// OAuth2AuthStyleHeader sends client_id/client_secret as HTTP Basic auth.
	OAuth2AuthStyleHeader = "header"
	// OAuth2AuthStyleBody sends them as form fields in the request body.
	OAuth2AuthStyleBody = "body"
)

// ExtractRule defines how to extract an auth token from a login response.
type ExtractRule struct {
	Source  ExtractSource `yaml:"source" json:"source"`
	Name    string        `yaml:"name,omitempty" json:"name,omitempty"`         // Cookie name or header name
	Path    string        `yaml:"path,omitempty" json:"path,omitempty"`         // JSONPath for json source
	ApplyAs string        `yaml:"apply_as,omitempty" json:"apply_as,omitempty"` // Header template, e.g. "Authorization: Bearer {value}"
	// Regex extraction fields (source: "regex")
	Pattern string `yaml:"pattern,omitempty" json:"pattern,omitempty"` // Regex pattern with capture group
	Group   int    `yaml:"group,omitempty" json:"group,omitempty"`     // Capture group index (default: 1)
}

// ExpectResponse defines validation rules for a login response.
type ExpectResponse struct {
	Status       []int  `yaml:"status,omitempty" json:"status,omitempty"`               // Acceptable status codes (e.g. [200, 201])
	BodyContains string `yaml:"body_contains,omitempty" json:"body_contains,omitempty"` // Response body must contain this string
}

// LoginStep defines a single step in a multi-step login flow.
type LoginStep struct {
	URL         string `yaml:"url" json:"url"`
	Method      string `yaml:"method" json:"method"`
	ContentType string `yaml:"content_type,omitempty" json:"content_type,omitempty"`
	// Headers are extra request headers for this step, applied after the
	// flow's own login.headers (a step header wins). Values support {var}
	// and the {{env:…}} / {{totp:…}} templates, like url and body.
	Headers map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
	Body    string            `yaml:"body,omitempty" json:"body,omitempty"`
	Extract []ExtractRule     `yaml:"extract,omitempty" json:"extract,omitempty"`
	Expect  *ExpectResponse   `yaml:"expect,omitempty" json:"expect,omitempty"`
}

// LoginFlow defines how to authenticate to get session credentials.
type LoginFlow struct {
	URL         string        `yaml:"url" json:"url"`
	Method      string        `yaml:"method" json:"method"`
	ContentType string        `yaml:"content_type,omitempty" json:"content_type,omitempty"`
	Body        string        `yaml:"body,omitempty" json:"body,omitempty"`
	Extract     []ExtractRule `yaml:"extract,omitempty" json:"extract,omitempty"`
	// Shorthand: type + token_path expand into extract rules automatically.
	Type      LoginType `yaml:"type,omitempty" json:"type,omitempty"`
	TokenPath string    `yaml:"token_path,omitempty" json:"token_path,omitempty"`
	// Response validation.
	Expect *ExpectResponse `yaml:"expect,omitempty" json:"expect,omitempty"`
	// Multi-step login flows. When set, URL/Method/Body/Extract on the parent are ignored.
	Steps []LoginStep `yaml:"steps,omitempty" json:"steps,omitempty"`
	// Headers are extra request headers sent with every login request: the
	// single request, each step (a step's own headers win), or the OAuth2
	// token request. Values support the {{env:…}} / {{totp:…}} templates.
	Headers map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`

	// OAuth2 token endpoint (type oauth2_client_credentials or
	// oauth2_refresh_token; see oauth.go). Every value supports the
	// {{env:…}} templates; ${ENV} is expanded when the file loads.
	TokenURL     string `yaml:"token_url,omitempty" json:"token_url,omitempty"`
	ClientID     string `yaml:"client_id,omitempty" json:"client_id,omitempty"`
	ClientSecret string `yaml:"client_secret,omitempty" json:"client_secret,omitempty"`
	// Scope is space- (or comma-) separated. Sent with client_credentials.
	Scope string `yaml:"scope,omitempty" json:"scope,omitempty"`
	// Audience is sent as the `audience` parameter with client_credentials.
	Audience     string `yaml:"audience,omitempty" json:"audience,omitempty"`
	RefreshToken string `yaml:"refresh_token,omitempty" json:"refresh_token,omitempty"`
	// AuthStyle is how the client authenticates: "header" (HTTP Basic) or
	// "body" (form fields). Empty tries header, then body.
	AuthStyle string `yaml:"auth_style,omitempty" json:"auth_style,omitempty"`

	// rawHeaders are the headers of a flow converted from a session's
	// login_request (the raw request's own); sent before Headers.
	rawHeaders map[string]string
	// discoverTokens marks a flow converted from login_request: with no
	// configured Extract, its rules are discovered from each login response,
	// as `auth load` does for a raw request.
	discoverTokens bool
}

// Session represents a named authentication identity used during scanning.
type Session struct {
	Name    string            `yaml:"name" json:"name"`
	Role    Role              `yaml:"role" json:"role"`
	Headers map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
	Login   *LoginFlow        `yaml:"login,omitempty" json:"login,omitempty"`
	// LoginRequest is a raw HTTP request string for the login flow.
	LoginRequest string `yaml:"login_request,omitempty" json:"login_request,omitempty"`
	// Check says how to tell whether the session is still logged in
	// (loggedin.go). Optional; scanning_strategy.session supplies defaults.
	Check *SessionCheck `yaml:"check,omitempty" json:"check,omitempty"`
	// Reauth says what a scan does once Check finds the session logged out.
	Reauth *SessionReauth `yaml:"reauth,omitempty" json:"reauth,omitempty"`

	// hydrated indicates whether the login flow has been executed.
	hydrated bool
	// expiresAt is when the credentials the last login produced expire, when
	// the login said so (an OAuth2 token's expires_in). Zero = unknown.
	expiresAt time.Time
}

// ExpiresAt is when the session's current credentials expire, as reported by
// the login that produced them (an OAuth2 token response's expires_in). Zero
// when the login did not say. A scan's LiveSession refreshes the credentials
// shortly before this time.
func (s *Session) ExpiresAt() time.Time {
	if s == nil {
		return time.Time{}
	}
	return s.expiresAt
}

// SessionConfig holds multiple sessions, used for --auth-config files (YAML or JSON).
type SessionConfig struct {
	Sessions []Session `yaml:"sessions" json:"sessions"`
}

// Validate checks that the session definition is well-formed.
func (s *Session) Validate() error {
	if s.Name == "" {
		return fmt.Errorf("session name is required")
	}
	switch s.Role {
	case RolePrimary, RoleCompare, "":
		// valid
	default:
		return fmt.Errorf("session %q: invalid role %q (must be 'primary' or 'compare')", s.Name, s.Role)
	}
	hasStatic := len(s.Headers) > 0
	// A Login converted from login_request is the same source, not a second one.
	hasLogin := s.Login != nil && !s.Login.discoverTokens
	hasRawLogin := s.LoginRequest != ""
	sources := 0
	if hasStatic {
		sources++
	}
	if hasLogin {
		sources++
	}
	if hasRawLogin {
		sources++
	}
	if sources > 1 {
		return fmt.Errorf("session %q: specify only one of headers, login, or login_request", s.Name)
	}
	if hasLogin {
		if err := s.Login.Validate(s.Name); err != nil {
			return err
		}
	}
	// check and reauth: the same rules auth lint reports, first error wins.
	for _, is := range append(lintCheck(s.Check, "check"), lintReauth(s, "reauth")...) {
		if is.Severity == "error" {
			return fmt.Errorf("session %q: %s: %s", s.Name, is.Field, is.Message)
		}
	}
	return nil
}

// Validate checks that a LoginFlow is well-formed.
func (lf *LoginFlow) Validate(sessionName string) error {
	// OAuth2 token endpoints: the same required fields lint reports.
	if lf.Type.IsOAuth2() {
		for _, is := range lintOAuth2Flow(lf, "login") {
			if is.Severity == "error" {
				return fmt.Errorf("session %q: %s: %s", sessionName, is.Field, is.Message)
			}
		}
		return nil
	}

	// Multi-step flows: validate each step instead of top-level fields.
	if len(lf.Steps) > 0 {
		for i, step := range lf.Steps {
			if step.URL == "" {
				return fmt.Errorf("session %q: steps[%d].url is required", sessionName, i)
			}
			if step.Method == "" {
				return fmt.Errorf("session %q: steps[%d].method is required", sessionName, i)
			}
		}
		// Last step must have extract rules or the parent must use type shorthand.
		lastStep := lf.Steps[len(lf.Steps)-1]
		if len(lastStep.Extract) == 0 {
			return fmt.Errorf("session %q: last step must have at least one extract rule", sessionName)
		}
		return nil
	}

	// Shorthand type: type + token_path is valid without explicit extract rules.
	if lf.Type != "" {
		switch lf.Type {
		case LoginTypeBearer:
			if lf.TokenPath == "" {
				return fmt.Errorf("session %q: login.token_path is required when type is \"bearer\"", sessionName)
			}
		case LoginTypeCookie:
			// No token_path needed for cookie type.
		default:
			return fmt.Errorf("session %q: unknown login type %q (must be %s)", sessionName, lf.Type, loginTypeList)
		}
		// URL and Method are still required.
		if lf.URL == "" {
			return fmt.Errorf("session %q: login.url is required", sessionName)
		}
		if lf.Method == "" {
			return fmt.Errorf("session %q: login.method is required", sessionName)
		}
		return nil
	}

	// Standard login flow validation.
	if lf.URL == "" {
		return fmt.Errorf("session %q: login.url is required", sessionName)
	}
	if lf.Method == "" {
		return fmt.Errorf("session %q: login.method is required", sessionName)
	}
	if len(lf.Extract) == 0 {
		return fmt.Errorf("session %q: login.extract requires at least one rule (or use type shorthand)", sessionName)
	}
	return nil
}

// NormalizeLoginFlow expands shorthand type/token_path into explicit extract rules
// and validates the URL. Called before execution; safe to call multiple times.
func NormalizeLoginFlow(lf *LoginFlow) {
	if lf == nil {
		return
	}
	// Expand type shorthand into extract rules if no explicit extract rules are set.
	if lf.Type != "" && len(lf.Extract) == 0 {
		switch lf.Type {
		case LoginTypeBearer:
			lf.Extract = expandBearerTokenPath(lf.TokenPath)
		case LoginTypeCookie:
			lf.Extract = []ExtractRule{{
				Source: ExtractCookie,
			}}
		}
	}

	// Auto-detect content type from body if not set.
	if lf.ContentType == "" && lf.Body != "" {
		if strings.HasPrefix(strings.TrimSpace(lf.Body), "{") {
			lf.ContentType = "application/json"
		}
	}
}

// expandBearerTokenPath parses token_path and returns the appropriate extract rule.
// Supported formats:
//   - ".token", ".data.access_token" → extract from JSON body (default)
//   - "header:X-JWT-Token"           → extract from response header
//   - empty                          → defaults to ".token" from JSON body
func expandBearerTokenPath(tokenPath string) []ExtractRule {
	if tokenPath == "" {
		return []ExtractRule{{
			Source:  ExtractJSON,
			Path:    ".token",
			ApplyAs: "Authorization: Bearer {value}",
		}}
	}

	// header:HeaderName → extract from response header.
	if after, ok := strings.CutPrefix(tokenPath, "header:"); ok {
		return []ExtractRule{{
			Source:  ExtractHeader,
			Name:    after,
			ApplyAs: "Authorization: Bearer {value}",
		}}
	}

	// Default: treat as JSON path.
	return []ExtractRule{{
		Source:  ExtractJSON,
		Path:    tokenPath,
		ApplyAs: "Authorization: Bearer {value}",
	}}
}

// ValidateExpect checks if an HTTP response satisfies the expect constraints.
func ValidateExpect(expect *ExpectResponse, statusCode int, body []byte) error {
	_, err := checkExpect(expect, statusCode, body)
	return err
}

// LoginURL returns the login URL for the session. For multi-step flows, returns
// the URL of the first step.
func (lf *LoginFlow) LoginURL() string {
	if len(lf.Steps) > 0 {
		return lf.Steps[0].URL
	}
	return lf.URL
}

// LintIssue represents a single validation issue found during linting.
type LintIssue struct {
	Field    string `json:"field"`    // dot-notation path, e.g. "sessions[0].login.url"
	Severity string `json:"severity"` // "error" or "warning"
	Message  string `json:"message"`
	// Line and Column locate the field in the source file (1-based); 0 when
	// the issue has no position (a missing field with no present parent, or a
	// document parsed without one).
	Line   int `json:"line,omitempty"`
	Column int `json:"column,omitempty"`
}

// LintSessionConfig performs detailed validation of a SessionConfig and returns
// all issues found, rather than stopping at the first error.
func LintSessionConfig(cfg *SessionConfig) []LintIssue {
	var issues []LintIssue

	if len(cfg.Sessions) == 0 {
		issues = append(issues, LintIssue{
			Field:    "sessions",
			Severity: "error",
			Message:  "no sessions defined",
		})
		return issues
	}

	primaryCount := 0
	names := map[string]int{}

	for i := range cfg.Sessions {
		prefix := fmt.Sprintf("sessions[%d]", i)
		s := &cfg.Sessions[i]
		issues = append(issues, lintSession(s, prefix)...)

		if s.Role == RolePrimary {
			primaryCount++
		}
		names[s.Name]++
	}

	if primaryCount == 0 {
		issues = append(issues, LintIssue{
			Field:    "sessions",
			Severity: "warning",
			Message:  "no session has role \"primary\" — first session will be auto-promoted",
		})
	}
	if primaryCount > 1 {
		issues = append(issues, LintIssue{
			Field:    "sessions",
			Severity: "error",
			Message:  fmt.Sprintf("multiple sessions have role \"primary\" (%d found)", primaryCount),
		})
	}
	for name, count := range names {
		if count > 1 {
			issues = append(issues, LintIssue{
				Field:    "sessions",
				Severity: "warning",
				Message:  fmt.Sprintf("duplicate session name %q (%d occurrences)", name, count),
			})
		}
	}

	return issues
}

func lintSession(s *Session, prefix string) []LintIssue {
	var issues []LintIssue

	if s.Name == "" {
		issues = append(issues, LintIssue{
			Field: yamlschema.JoinPath(prefix, "name"), Severity: "error",
			Message: "session name is required",
		})
	}

	switch s.Role {
	case RolePrimary, RoleCompare, "":
		// ok
	default:
		issues = append(issues, LintIssue{
			Field: yamlschema.JoinPath(prefix, "role"), Severity: "error",
			Message: fmt.Sprintf("invalid role %q (must be \"primary\" or \"compare\")", s.Role),
		})
	}

	hasStatic := len(s.Headers) > 0
	hasLogin := s.Login != nil
	hasRawLogin := s.LoginRequest != ""
	sources := 0
	if hasStatic {
		sources++
	}
	if hasLogin {
		sources++
	}
	if hasRawLogin {
		sources++
	}
	if sources == 0 {
		issues = append(issues, LintIssue{
			Field: prefix, Severity: "warning",
			Message: "session has no auth source (no headers, login, or login_request)",
		})
	}
	if sources > 1 {
		issues = append(issues, LintIssue{
			Field: prefix, Severity: "error",
			Message: "specify only one of headers, login, or login_request",
		})
	}

	if hasLogin {
		issues = append(issues, lintLoginFlow(s.Login, yamlschema.JoinPath(prefix, "login"))...)
	}
	issues = append(issues, lintCheck(s.Check, yamlschema.JoinPath(prefix, "check"))...)
	issues = append(issues, lintReauth(s, yamlschema.JoinPath(prefix, "reauth"))...)

	return issues
}

func lintLoginFlow(lf *LoginFlow, prefix string) []LintIssue {
	var issues []LintIssue

	issues = append(issues, lintHeaderMap(lf.Headers, prefix+".headers")...)
	issues = append(issues, lintTemplates(lf.URL, prefix+".url")...)
	issues = append(issues, lintTemplates(lf.Body, prefix+".body")...)

	// OAuth2 token endpoints.
	if lf.Type.IsOAuth2() {
		return append(issues, lintOAuth2Flow(lf, prefix)...)
	}
	if oauthOnly := oauth2FieldsSet(lf); len(oauthOnly) > 0 {
		issues = append(issues, LintIssue{
			Field: prefix + "." + oauthOnly[0], Severity: "warning",
			Message: fmt.Sprintf("%s apply only to type oauth2_client_credentials / oauth2_refresh_token and are ignored here", strings.Join(oauthOnly, ", ")),
		})
	}

	// Multi-step flows.
	if len(lf.Steps) > 0 {
		if lf.URL != "" || lf.Method != "" {
			issues = append(issues, LintIssue{
				Field: prefix, Severity: "warning",
				Message: "url/method on login are ignored when steps are defined",
			})
		}
		for i, step := range lf.Steps {
			stepPrefix := fmt.Sprintf("%s.steps[%d]", prefix, i)
			issues = append(issues, lintLoginStep(&step, stepPrefix)...)
		}
		lastStep := lf.Steps[len(lf.Steps)-1]
		if len(lastStep.Extract) == 0 {
			issues = append(issues, LintIssue{
				Field: fmt.Sprintf("%s.steps[%d].extract", prefix, len(lf.Steps)-1), Severity: "error",
				Message: "last step must have at least one extract rule",
			})
		}
		return issues
	}

	// Type shorthand.
	if lf.Type != "" {
		switch lf.Type {
		case LoginTypeBearer:
			if lf.TokenPath == "" {
				issues = append(issues, LintIssue{
					Field: prefix + ".token_path", Severity: "error",
					Message: "token_path is required when type is \"bearer\" (e.g. \".token\" for JSON body, \"header:X-JWT-Token\" for response header)",
				})
			} else if after, ok := strings.CutPrefix(lf.TokenPath, "header:"); ok && strings.TrimSpace(after) == "" {
				issues = append(issues, LintIssue{
					Field: prefix + ".token_path", Severity: "error",
					Message: "header name is empty in token_path \"header:\" — expected \"header:HeaderName\"",
				})
			}
		case LoginTypeCookie:
			if lf.TokenPath != "" {
				issues = append(issues, LintIssue{
					Field: prefix + ".token_path", Severity: "warning",
					Message: "token_path is ignored when type is \"cookie\"",
				})
			}
		default:
			issues = append(issues, LintIssue{
				Field: prefix + ".type", Severity: "error",
				Message: fmt.Sprintf("unknown login type %q (must be %s)", lf.Type, loginTypeList),
			})
		}
		if len(lf.Extract) > 0 {
			issues = append(issues, LintIssue{
				Field: prefix + ".extract", Severity: "warning",
				Message: "extract rules are ignored when type shorthand is used",
			})
		}
	}

	// URL validation.
	if lf.URL == "" {
		issues = append(issues, LintIssue{
			Field: prefix + ".url", Severity: "error",
			Message: "login URL is required",
		})
	} else {
		if u, err := url.Parse(lf.URL); err != nil {
			issues = append(issues, LintIssue{
				Field: prefix + ".url", Severity: "error",
				Message: fmt.Sprintf("invalid URL: %v", err),
			})
		} else if u.Scheme != "http" && u.Scheme != "https" {
			issues = append(issues, LintIssue{
				Field: prefix + ".url", Severity: "error",
				Message: fmt.Sprintf("URL scheme must be http or https, got %q", u.Scheme),
			})
		}
	}

	if lf.Method == "" {
		issues = append(issues, LintIssue{
			Field: prefix + ".method", Severity: "error",
			Message: "login method is required",
		})
	}

	// Extract rules validation (only required when no type shorthand).
	if lf.Type == "" && len(lf.Extract) == 0 {
		issues = append(issues, LintIssue{
			Field: prefix + ".extract", Severity: "error",
			Message: "at least one extract rule is required (or use type shorthand)",
		})
	}

	for i, rule := range lf.Extract {
		rulePrefix := fmt.Sprintf("%s.extract[%d]", prefix, i)
		issues = append(issues, lintExtractRule(&rule, rulePrefix)...)
	}

	// Expect validation.
	if lf.Expect != nil {
		issues = append(issues, lintExpect(lf.Expect, prefix+".expect")...)
	}

	return issues
}

func lintLoginStep(step *LoginStep, prefix string) []LintIssue {
	var issues []LintIssue

	if step.URL == "" {
		issues = append(issues, LintIssue{
			Field: prefix + ".url", Severity: "error",
			Message: "step URL is required",
		})
	}
	if step.Method == "" {
		issues = append(issues, LintIssue{
			Field: prefix + ".method", Severity: "error",
			Message: "step method is required",
		})
	}
	issues = append(issues, lintTemplates(step.URL, prefix+".url")...)
	issues = append(issues, lintTemplates(step.Body, prefix+".body")...)
	issues = append(issues, lintHeaderMap(step.Headers, prefix+".headers")...)
	for i, rule := range step.Extract {
		rulePrefix := fmt.Sprintf("%s.extract[%d]", prefix, i)
		issues = append(issues, lintExtractRule(&rule, rulePrefix)...)
	}
	if step.Expect != nil {
		issues = append(issues, lintExpect(step.Expect, prefix+".expect")...)
	}
	return issues
}

// loginTypeList is the accepted login.type values, for error messages.
const loginTypeList = `"bearer", "cookie", "oauth2_client_credentials" or "oauth2_refresh_token"`

// lintHeaderMap checks a login.headers / steps[].headers map: names must be
// non-empty tokens, values may carry templates.
func lintHeaderMap(h map[string]string, prefix string) []LintIssue {
	var issues []LintIssue
	for _, name := range headerNames(h) {
		field := yamlschema.JoinPath(prefix, name)
		if strings.TrimSpace(name) == "" || strings.ContainsAny(name, " :\t\r\n") {
			issues = append(issues, LintIssue{
				Field: field, Severity: "error",
				Message: fmt.Sprintf("invalid header name %q", name),
			})
		}
		issues = append(issues, lintTemplates(h[name], field)...)
	}
	return issues
}

func lintExtractRule(rule *ExtractRule, prefix string) []LintIssue {
	var issues []LintIssue

	switch rule.Source {
	case ExtractCookie:
		// Name is optional (empty = all cookies).
	case ExtractJSON:
		if rule.Path == "" {
			issues = append(issues, LintIssue{
				Field: prefix + ".path", Severity: "error",
				Message: "path is required for json extraction",
			})
		}
		if rule.ApplyAs == "" {
			issues = append(issues, LintIssue{
				Field: prefix + ".apply_as", Severity: "error",
				Message: "apply_as is required for json extraction",
			})
		}
	case ExtractHeader:
		if rule.Name == "" {
			issues = append(issues, LintIssue{
				Field: prefix + ".name", Severity: "error",
				Message: "name is required for header extraction",
			})
		}
	case ExtractRegex:
		if rule.Pattern == "" {
			issues = append(issues, LintIssue{
				Field: prefix + ".pattern", Severity: "error",
				Message: "pattern is required for regex extraction",
			})
		}
		if rule.ApplyAs == "" {
			issues = append(issues, LintIssue{
				Field: prefix + ".apply_as", Severity: "error",
				Message: "apply_as is required for regex extraction",
			})
		}
	case "":
		issues = append(issues, LintIssue{
			Field: prefix + ".source", Severity: "error",
			Message: "extract source is required (cookie, json, header, or regex)",
		})
	default:
		issues = append(issues, LintIssue{
			Field: prefix + ".source", Severity: "error",
			Message: fmt.Sprintf("unknown extract source %q (must be cookie, json, header, or regex)", rule.Source),
		})
	}

	// Validate apply_as format if present.
	if rule.ApplyAs != "" && !strings.Contains(rule.ApplyAs, ":") {
		issues = append(issues, LintIssue{
			Field: prefix + ".apply_as", Severity: "error",
			Message: fmt.Sprintf("apply_as must be in \"HeaderName: value\" format, got %q", rule.ApplyAs),
		})
	}

	return issues
}

func lintExpect(expect *ExpectResponse, prefix string) []LintIssue {
	var issues []LintIssue
	if len(expect.Status) == 0 && expect.BodyContains == "" {
		issues = append(issues, LintIssue{
			Field: prefix, Severity: "warning",
			Message: "expect block is empty (no status codes or body_contains)",
		})
	}
	for i, code := range expect.Status {
		if code < 100 || code > 599 {
			issues = append(issues, LintIssue{
				Field:    fmt.Sprintf("%s.status[%d]", prefix, i),
				Severity: "error",
				Message:  fmt.Sprintf("invalid HTTP status code %d", code),
			})
		}
	}
	return issues
}

// IsHydrated returns true if the session has been populated with credentials.
func (s *Session) IsHydrated() bool {
	return s.hydrated || len(s.Headers) > 0
}

// HeaderSlice converts the session headers map to a slice of "Name: Value" strings,
// compatible with types.Options.Headers.
func (s *Session) HeaderSlice() []string {
	if len(s.Headers) == 0 {
		return nil
	}
	result := make([]string, 0, len(s.Headers))
	for k, v := range s.Headers {
		result = append(result, k+": "+v)
	}
	return result
}

// ParseInlineSession parses a CLI --auth flag value in "name:Header:value" format.
// Example: "admin:Cookie:session=abc" → Session{Name:"admin", Headers:{"Cookie":"session=abc"}}
func ParseInlineSession(s string) (*Session, error) {
	// Format: name:HeaderName:HeaderValue
	parts := strings.SplitN(s, ":", 3)
	if len(parts) < 3 {
		// Common mistake: "name:value" without the header-name field in the
		// middle (e.g. "user1:session=abc" instead of "user1:Cookie:session=abc").
		// When the second field looks like a header *value* rather than a header
		// name, point at the missing field and suggest a copy-pasteable fix.
		if len(parts) == 2 {
			name := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			if name != "" && looksLikeAuthValue(value) {
				suggestion := fmt.Sprintf("%s:%s:%s", name, guessAuthHeader(value), value)
				return nil, fmt.Errorf("invalid --auth format %q: missing the header-name field — "+
					"the format is name:Header:value, but you provided only name:value. "+
					"Did you mean %q? (the header name, e.g. Cookie, goes between the session name and the value)",
					s, suggestion)
			}
		}
		return nil, fmt.Errorf("invalid --auth format %q: expected name:Header:value (e.g. admin:Cookie:session=abc)", s)
	}
	name := strings.TrimSpace(parts[0])
	headerName := strings.TrimSpace(parts[1])
	headerValue := strings.TrimSpace(parts[2])
	if name == "" || headerName == "" {
		return nil, fmt.Errorf("invalid --auth format %q: name and header name cannot be empty", s)
	}
	return &Session{
		Name: name,
		Role: RoleCompare, // default; first session auto-promoted to primary by manager
		Headers: map[string]string{
			headerName: headerValue,
		},
	}, nil
}

// looksLikeAuthValue reports whether s appears to be a header *value* (a cookie
// string, bearer token, etc.) rather than a header *name*. HTTP header names are
// RFC 7230 tokens — letters, digits, and a few symbols, but never '=', ' ', ';',
// or '/'. Any of those characters means the user almost certainly pasted a value
// and omitted the header-name field.
func looksLikeAuthValue(s string) bool {
	return strings.ContainsAny(s, "= ;/")
}

// guessAuthHeader infers the most likely header name for an inline auth value
// whose header field was omitted, so the error message can suggest a concrete
// correction. Bearer/Basic credentials map to Authorization; everything else
// defaults to Cookie, by far the most common case.
func guessAuthHeader(value string) string {
	lower := strings.ToLower(value)
	switch {
	case strings.HasPrefix(lower, "bearer "), strings.HasPrefix(lower, "basic "):
		return "Authorization"
	default:
		return "Cookie"
	}
}
