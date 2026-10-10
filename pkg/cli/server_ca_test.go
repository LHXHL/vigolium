package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The trust-plan builder is pure: every platform's commands are checked here
// from any platform.
func TestBuildCATrustPlan(t *testing.T) {
	const (
		cert = "/home/u/.vigolium/ca/vigolium-ca.pem"
		home = "/home/u"
		cn   = "Vigolium Ingest Proxy CA"
	)
	argvs := func(p caTrustPlan) []string {
		out := make([]string, len(p.Steps))
		for i, s := range p.Steps {
			out[i] = strings.Join(s.Argv, " ")
		}
		return out
	}

	cases := []struct {
		name, goos, family, action string
		root                       bool
		platform                   string
		want                       []string
	}{
		{"macos install", "darwin", "", caActionInstall, false, "macos", []string{
			"security add-trusted-cert -r trustRoot -k /home/u/Library/Keychains/login.keychain-db " + cert,
		}},
		{"macos uninstall", "darwin", "", caActionUninstall, false, "macos", []string{
			"security remove-trusted-cert " + cert,
			"security delete-certificate -c " + cn + " /home/u/Library/Keychains/login.keychain-db",
		}},
		{"debian install", "linux", linuxFamilyDebian, caActionInstall, false, "linux-debian", []string{
			"sudo cp " + cert + " /usr/local/share/ca-certificates/vigolium.crt",
			"sudo update-ca-certificates",
		}},
		{"debian install as root", "linux", linuxFamilyDebian, caActionInstall, true, "linux-debian", []string{
			"cp " + cert + " /usr/local/share/ca-certificates/vigolium.crt",
			"update-ca-certificates",
		}},
		{"debian uninstall", "linux", linuxFamilyDebian, caActionUninstall, false, "linux-debian", []string{
			"sudo rm -f /usr/local/share/ca-certificates/vigolium.crt",
			"sudo update-ca-certificates --fresh",
		}},
		{"rhel install", "linux", linuxFamilyRHEL, caActionInstall, false, "linux-rhel", []string{
			"sudo cp " + cert + " /etc/pki/ca-trust/source/anchors/vigolium.pem",
			"sudo update-ca-trust",
		}},
		{"rhel uninstall", "linux", linuxFamilyRHEL, caActionUninstall, false, "linux-rhel", []string{
			"sudo rm -f /etc/pki/ca-trust/source/anchors/vigolium.pem",
			"sudo update-ca-trust",
		}},
		{"windows install", "windows", "", caActionInstall, false, "windows", []string{
			"certutil -user -addstore Root " + cert,
		}},
		{"windows uninstall", "windows", "", caActionUninstall, false, "windows", []string{
			"certutil -user -delstore Root " + cn,
		}},
		{"unknown linux has notes only", "linux", "", caActionInstall, false, "linux", []string{}},
		{"unknown os has notes only", "plan9", "", caActionInstall, false, "plan9", []string{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan, err := buildCATrustPlan(tc.goos, tc.family, tc.action, cert, home, cn, tc.root)
			require.NoError(t, err)
			assert.Equal(t, tc.platform, plan.Platform)
			assert.Equal(t, tc.want, argvs(plan))
			assert.NotEmpty(t, plan.Notes, "every plan carries the browser-store note")
		})
	}

	_, err := buildCATrustPlan("linux", linuxFamilyDebian, "wipe", cert, home, cn, false)
	assert.Error(t, err)
}

func TestQuoteArgv(t *testing.T) {
	assert.Equal(t, "security delete-certificate -c 'Vigolium Ingest Proxy CA' /k",
		quoteArgv([]string{"security", "delete-certificate", "-c", "Vigolium Ingest Proxy CA", "/k"}))
	assert.Equal(t, `echo 'it'\''s' ''`, quoteArgv([]string{"echo", "it's", ""}))
}

// runCAPrint runs `server ca print` and returns its stdout.
func runCAPrint(t *testing.T) string {
	t.Helper()
	var err error
	out := captureStdout(t, func() { err = runServerCAPrint(serverCAPrintCmd, nil) })
	require.NoError(t, err)
	return out
}

// `server ca print -j` is one envelope whose single item names the cert's
// path, sha256, subject and expiry; plain `print` is the PEM itself.
func TestServerCAPrint(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	prevJSON, prevOut := globalJSON, serverCAOut
	t.Cleanup(func() { globalJSON, serverCAOut = prevJSON, prevOut })
	serverCAOut = ""

	globalJSON = false
	pemOut := runCAPrint(t)
	assert.True(t, strings.HasPrefix(pemOut, "-----BEGIN CERTIFICATE-----"), pemOut)

	globalJSON = true
	jsonOut := runCAPrint(t)
	var doc struct {
		Items []map[string]any `json:"items"`
	}
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(jsonOut)), &doc), jsonOut)
	require.Len(t, doc.Items, 1)
	item := doc.Items[0]
	assert.True(t, strings.HasSuffix(item["path"].(string), "vigolium-ca.pem"))
	assert.Len(t, item["sha256"], 64)
	assert.Contains(t, item["subject"], "Vigolium Ingest Proxy CA")
	assert.Regexp(t, `^\d{4}-\d{2}-\d{2}T`, item["not_after"])

	// The same CA on a second call: stable fingerprint.
	again := runCAPrint(t)
	assert.Contains(t, again, item["sha256"].(string))
}

// --export-ca stays as a hidden alias, and the ca group is wired under server.
func TestServerCAWiring(t *testing.T) {
	f := serverCmd.Flags().Lookup("export-ca")
	require.NotNil(t, f)
	assert.True(t, f.Hidden)

	var names []string
	for _, c := range serverCACmd.Commands() {
		names = append(names, c.Name())
	}
	assert.ElementsMatch(t, []string{"print", "path", "install", "uninstall"}, names)
	found, _, err := serverCmd.Find([]string{"ca", "install"})
	require.NoError(t, err)
	assert.Equal(t, serverCAInstallCmd, found)
	assert.NotNil(t, serverCAInstallCmd.Flags().Lookup("yes"))
}
