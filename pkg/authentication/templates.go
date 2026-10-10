package authentication

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
)

// templates.go expands the function templates a login flow may carry in its
// url, body, header values and OAuth2 fields. They are evaluated when the
// login RUNS (each login, each re-login), not when the file loads, so a TOTP
// code is fresh for every attempt and a secret never has to sit in the file:
//
//	{{env:NAME}}                the value of environment variable NAME
//	{{totp:NAME}}               the current TOTP code for the base32 secret in $NAME
//	{{totp_secret_file:PATH}}   the current TOTP code for the base32 secret in file PATH
//
// ${NAME} (expanded once, at load) keeps working; {{env:NAME}} differs only in
// being read at login time. A missing variable or unreadable file fails the
// login with the template named, never sends an empty value.

// templateRe matches {{func:arg}}. The function is lowercase letters and
// underscores; the argument runs to the closing braces.
var templateRe = regexp.MustCompile(`\{\{\s*([a-z_]+)\s*:\s*([^{}]*?)\s*\}\}`)

// Template function names.
const (
	templateEnv            = "env"
	templateTOTP           = "totp"
	templateTOTPSecretFile = "totp_secret_file"
)

// templateNow is the clock TOTP codes are computed against. A test seam.
var templateNow = time.Now

// envNameRe is a portable environment variable name.
var envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// base32SecretRe is what a literal TOTP secret looks like: 16+ characters of
// the RFC 4648 base32 alphabet, optionally padded.
var base32SecretRe = regexp.MustCompile(`^[A-Z2-7]{16,}=*$`)

// expandTemplates replaces every {{func:arg}} in s. The first template that
// cannot be evaluated fails the whole expansion.
func expandTemplates(s string) (string, error) {
	if !strings.Contains(s, "{{") {
		return s, nil
	}
	var firstErr error
	out := templateRe.ReplaceAllStringFunc(s, func(m string) string {
		if firstErr != nil {
			return m
		}
		sub := templateRe.FindStringSubmatch(m)
		v, err := evalTemplate(sub[1], sub[2])
		if err != nil {
			firstErr = fmt.Errorf("template %s: %w", m, err)
			return m
		}
		return v
	})
	if firstErr != nil {
		return "", firstErr
	}
	return out, nil
}

func evalTemplate(fn, arg string) (string, error) {
	switch fn {
	case templateEnv:
		v, ok := os.LookupEnv(arg)
		if !ok {
			return "", fmt.Errorf("environment variable %q is not set", arg)
		}
		return v, nil
	case templateTOTP:
		secret, ok := os.LookupEnv(arg)
		if !ok {
			return "", fmt.Errorf("environment variable %q (the TOTP secret) is not set", arg)
		}
		return totpCode(secret)
	case templateTOTPSecretFile:
		data, err := os.ReadFile(expandHome(arg))
		if err != nil {
			return "", fmt.Errorf("read TOTP secret: %w", err)
		}
		return totpCode(string(data))
	default:
		return "", fmt.Errorf("unknown template function %q (use env, totp or totp_secret_file)", fn)
	}
}

// totpCode is the RFC 6238 code (SHA-1, 6 digits, 30s) for secret now. The
// secret is trimmed and spaces dropped, as authenticator apps display it.
func totpCode(secret string) (string, error) {
	secret = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	if secret == "" {
		return "", fmt.Errorf("TOTP secret is empty")
	}
	code, err := totp.GenerateCode(secret, templateNow())
	if err != nil {
		return "", fmt.Errorf("invalid TOTP secret: %w", err)
	}
	return code, nil
}

func expandHome(p string) string {
	if rest, ok := strings.CutPrefix(p, "~/"); ok {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, rest)
		}
	}
	return p
}

// substituteVars expands the {{func:arg}} templates in s, then replaces
// {varname} placeholders with values a previous step extracted. Templates go
// first so a value the server returned is never itself template-expanded.
func substituteVars(s string, vars map[string]string) (string, error) {
	s, err := expandTemplates(s)
	if err != nil {
		return "", err
	}
	for k, v := range vars {
		s = strings.ReplaceAll(s, "{"+k+"}", v)
	}
	return s, nil
}

// substituteHeaders is substituteVars over every value of h.
func substituteHeaders(h map[string]string, vars map[string]string) (map[string]string, error) {
	if len(h) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(h))
	for k, v := range h {
		sv, err := substituteVars(v, vars)
		if err != nil {
			return nil, fmt.Errorf("header %s: %w", k, err)
		}
		out[k] = sv
	}
	return out, nil
}

// lintTemplates reports the problems `auth lint` can see in s's templates
// without evaluating them: an unknown function, a missing argument, an
// argument that is not a variable name, and a literal base32 secret where the
// NAME of a variable holding it belongs.
func lintTemplates(s, field string) []LintIssue {
	if !strings.Contains(s, "{{") {
		return nil
	}
	var issues []LintIssue
	for _, m := range templateRe.FindAllStringSubmatch(s, -1) {
		fn, arg := m[1], m[2]
		switch fn {
		case templateEnv, templateTOTP:
			switch {
			case arg == "":
				issues = append(issues, LintIssue{Field: field, Severity: "error",
					Message: fmt.Sprintf("%s needs an environment variable name", m[0])})
			case fn == templateTOTP && base32SecretRe.MatchString(arg):
				issues = append(issues, LintIssue{Field: field, Severity: "warning",
					Message: fmt.Sprintf("%s looks like a literal base32 TOTP secret; {{totp:NAME}} takes the NAME of an environment variable holding the secret (or use {{totp_secret_file:PATH}}), so the secret stays out of the file", m[0])})
			case !envNameRe.MatchString(arg):
				issues = append(issues, LintIssue{Field: field, Severity: "error",
					Message: fmt.Sprintf("%s: %q is not an environment variable name", m[0], arg)})
			}
		case templateTOTPSecretFile:
			if arg == "" {
				issues = append(issues, LintIssue{Field: field, Severity: "error",
					Message: fmt.Sprintf("%s needs a file path", m[0])})
			}
		default:
			issues = append(issues, LintIssue{Field: field, Severity: "error",
				Message: fmt.Sprintf("%s: unknown template function %q (use env, totp or totp_secret_file)", m[0], fn)})
		}
	}
	return issues
}
