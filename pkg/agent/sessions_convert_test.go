package agent

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/authentication"
)

// Native sessions survive native → agent → native for everything the agent
// format carries; flows it cannot carry (steps, OAuth2) keep their headers
// instead of becoming a broken single-request login.
func TestSessionsToAgentSessionConfig_RoundTrip(t *testing.T) {
	native := []*authentication.Session{
		{Name: "static", Role: authentication.RolePrimary, Headers: map[string]string{"Cookie": "sid=1", "X-Api-Key": "k"}},
		{Name: "login", Role: authentication.RoleCompare, Login: &authentication.LoginFlow{
			URL: "https://app.test/login", Method: "POST", ContentType: "application/json",
			Body: `{"u":"a","p":"b"}`, Type: authentication.LoginTypeBearer, TokenPath: ".token",
			Expect: &authentication.ExpectResponse{Status: []int{200}, BodyContains: "token"},
			Extract: []authentication.ExtractRule{
				{Source: authentication.ExtractJSON, Path: ".token", ApplyAs: "Authorization: Bearer {value}"},
				{Source: authentication.ExtractRegex, Pattern: `csrf=(\w+)`, Group: 1, ApplyAs: "X-CSRF: {value}"},
			},
		}},
		{Name: "oauth", Role: authentication.RoleCompare, Headers: map[string]string{"Authorization": "Bearer at"},
			Login: &authentication.LoginFlow{Type: authentication.LoginTypeOAuth2ClientCredentials, TokenURL: "https://idp.test/token"}},
	}

	cfg := SessionsToAgentSessionConfig(native)
	require.NotNil(t, cfg)
	require.Len(t, cfg.Sessions, 3)
	assert.Nil(t, cfg.Sessions[2].Login, "OAuth2 has no agent-format login")

	back := AgentSessionConfigToSessions(cfg)
	require.Len(t, back, 3)
	for i := range native {
		assert.Equal(t, native[i].Name, back[i].Name)
		assert.Equal(t, native[i].Role, back[i].Role)
		assert.Equal(t, native[i].Headers, back[i].Headers)
	}
	assert.Equal(t, native[1].Login, back[1].Login)
	assert.Nil(t, back[2].Login)
}
