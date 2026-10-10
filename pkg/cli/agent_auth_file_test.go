package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/authentication"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
)

const g16bOAuthSession = `name: svc
role: primary
login:
  type: oauth2_client_credentials
  token_url: https://idp.example.test/oauth/token
  client_id: scanner
  client_secret: "${G16B_CLI_SECRET}"
  auth_style: body
check:
  url: /me
`

const g16bStepsSession = `sessions:
  - name: mfa
    role: compare
    login:
      headers:
        X-Client: vigolium
      steps:
        - url: https://app.example.test/login
          method: POST
          body: '{"p":"pa$$word"}'
          headers:
            X-OTP: "{{totp:G16B_TOTP}}"
          extract:
            - source: json
              path: .token
              apply_as: "Authorization: Bearer {value}"
`

func writeG16bFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	return p
}

func TestAgentAuthFileFlags(t *testing.T) {
	for _, tc := range []struct {
		name  string
		flags *pflag.FlagSet
	}{
		{"swarm", agentSwarmCmd.Flags()},
		{"autopilot", agentAutopilotCmd.Flags()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := tc.flags.Lookup("auth-file")
			require.NotNil(t, f)
			assert.Equal(t, "stringArray", f.Value.Type(), "repeatable, commas literal")
			// The scan's --session-file alias resolves to the same flag.
			assert.Same(t, f, tc.flags.Lookup("session-file"))
		})
	}
	assert.Contains(t, agentSwarmCmd.Flags().Lookup("auth-config").Usage, "agent-format")
}

func TestResolveSwarmAuth(t *testing.T) {
	t.Setenv("G16B_CLI_SECRET", "s3cret")
	dir := t.TempDir()
	sessionDir := t.TempDir()
	settings := &config.Settings{}
	oauth := writeG16bFile(t, dir, "oauth.yaml", g16bOAuthSession)
	steps := writeG16bFile(t, dir, "steps.yaml", g16bStepsSession)

	t.Run("mutually exclusive", func(t *testing.T) {
		_, err := resolveSwarmAuth(settings, []string{oauth}, oauth, sessionDir)
		require.Error(t, err)
		var usage clicommon.UsageError
		assert.True(t, errors.As(err, &usage), "a usage error (exit 2)")
	})

	t.Run("neither", func(t *testing.T) {
		src, err := resolveSwarmAuth(settings, nil, "", sessionDir)
		require.NoError(t, err)
		assert.Nil(t, src)
	})

	t.Run("one file is used as is", func(t *testing.T) {
		src, err := resolveSwarmAuth(settings, []string{oauth}, "", sessionDir)
		require.NoError(t, err)
		assert.Equal(t, oauth, src.Path)
		require.Len(t, src.Sessions, 1)
		assert.Equal(t, "s3cret", src.Sessions[0].Login.ClientSecret)
		require.NotNil(t, src.Config)
		assert.Nil(t, src.Config.Sessions[0].Login, "an OAuth2 flow has no agent-format equivalent")
	})

	t.Run("several files merge losslessly", func(t *testing.T) {
		src, err := resolveSwarmAuth(settings, []string{oauth, steps}, "", sessionDir)
		require.NoError(t, err)
		assert.Equal(t, filepath.Join(sessionDir, "auth-config.yaml"), src.Path)
		raw, err := os.ReadFile(src.Path)
		require.NoError(t, err)
		assert.Contains(t, string(raw), "${G16B_CLI_SECRET}", "env refs are expanded once, by the loader")
		assert.Contains(t, string(raw), "pa$$word")
		info, err := os.Stat(src.Path)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

		// What the native phase loads equals what the files say.
		reloaded, err := authentication.LoadFromAuthFiles([]string{src.Path}, "")
		require.NoError(t, err)
		direct, err := authentication.LoadFromAuthFiles([]string{oauth, steps}, "")
		require.NoError(t, err)
		require.Len(t, reloaded, 2)
		for i := range direct {
			assert.Equal(t, direct[i].Name, reloaded[i].Name)
			assert.Equal(t, direct[i].Role, reloaded[i].Role)
			assert.Equal(t, direct[i].Login, reloaded[i].Login)
			assert.Equal(t, direct[i].Check, reloaded[i].Check)
		}
		assert.Equal(t, "s3cret", reloaded[0].Login.ClientSecret)
		assert.Equal(t, "{{totp:G16B_TOTP}}", reloaded[1].Login.Steps[0].Headers["X-OTP"])
	})

	t.Run("native file via --auth-config is loaded as --auth-file", func(t *testing.T) {
		src, err := resolveSwarmAuth(settings, nil, steps, sessionDir)
		require.NoError(t, err)
		assert.Equal(t, steps, src.Path)
		require.Len(t, src.Sessions, 1)
	})

	t.Run("agent-format --auth-config is used verbatim", func(t *testing.T) {
		agentCfg := writeG16bFile(t, dir, "session-config.json",
			`{"sessions":[{"name":"a","role":"primary","login":{"url":"https://x.test/login","method":"POST","expect":{"status":["200"]},"type":"cookie"}}]}`)
		src, err := resolveSwarmAuth(settings, nil, agentCfg, sessionDir)
		require.NoError(t, err)
		assert.Equal(t, agentCfg, src.Path)
		assert.Nil(t, src.Sessions)
	})

	t.Run("invalid file fails before the run", func(t *testing.T) {
		bad := writeG16bFile(t, dir, "bad.yaml", "name: x\nlogin:\n  type: oauth2_refresh_token\n  token_url: https://idp.test/token\n")
		_, err := resolveSwarmAuth(settings, []string{bad}, "", sessionDir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "refresh_token")
	})
}
