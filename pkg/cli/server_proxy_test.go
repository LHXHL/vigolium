package cli

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/config"
)

// proxyFlagCmd is a throwaway command carrying the server's proxy flags, so a
// test can mark them Changed without touching the real serverCmd.
func proxyFlagCmd(t *testing.T, so *serverOptions, args ...string) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: "server"}
	fs := cmd.Flags()
	fs.StringVar(&so.Host, "host", defaultServerHost, "")
	fs.IntVar(&so.IngestProxyPort, "ingest-proxy-port", 0, "")
	fs.StringVar(&so.IngestProxyHost, "ingest-proxy-host", "127.0.0.1", "")
	fs.StringVar(&so.ProxyToken, "proxy-token", "", "")
	fs.StringArrayVar(&so.ProxyAllow, "proxy-allow", nil, "")
	require.NoError(t, fs.Parse(args))
	return cmd
}

func TestServerBindDefaultsAreLoopback(t *testing.T) {
	assert.Equal(t, "127.0.0.1", serverCmd.Flags().Lookup("host").DefValue)
	assert.Equal(t, "127.0.0.1", serverCmd.Flags().Lookup("ingest-proxy-host").DefValue)
}

func TestResolveServerHostEnv(t *testing.T) {
	so := &serverOptions{}
	cmd := proxyFlagCmd(t, so)
	t.Setenv(serverHostEnv, "0.0.0.0")
	assert.Equal(t, "0.0.0.0", resolveServerHost(cmd, so.Host), "env fills an unset --host")

	cmd = proxyFlagCmd(t, so, "--host", "10.0.0.5")
	assert.Equal(t, "10.0.0.5", resolveServerHost(cmd, so.Host), "--host wins over the env")
}

// A routable proxy bind with neither a token nor an allow-list refuses to
// start, as a usage error (exit 2) naming the fix.
func TestResolveIngestProxyAuthRefusesOpenBind(t *testing.T) {
	so := &serverOptions{}
	cmd := proxyFlagCmd(t, so, "--ingest-proxy-port", "9003", "--ingest-proxy-host", "0.0.0.0")
	_, _, err := resolveIngestProxyAuth(cmd, so, &config.ServerConfig{})
	require.Error(t, err)
	assert.Equal(t, 2, classifyExitCode(err))
	assert.Contains(t, err.Error(), "--proxy-token")

	so = &serverOptions{}
	cmd = proxyFlagCmd(t, so, "--ingest-proxy-port", "9003", "--ingest-proxy-host", "0.0.0.0", "--proxy-token", "t")
	host, auth, err := resolveIngestProxyAuth(cmd, so, &config.ServerConfig{})
	require.NoError(t, err)
	assert.Equal(t, "0.0.0.0", host)
	assert.Equal(t, "t", auth.Token)

	so = &serverOptions{}
	cmd = proxyFlagCmd(t, so, "--ingest-proxy-port", "9003", "--ingest-proxy-host", "0.0.0.0",
		"--proxy-allow", "10.0.0.0/8", "--proxy-allow", "192.168.1.4")
	_, auth, err = resolveIngestProxyAuth(cmd, so, &config.ServerConfig{})
	require.NoError(t, err)
	assert.Len(t, auth.Allow, 2)

	// No proxy port: nothing listens, so nothing to refuse.
	so = &serverOptions{}
	cmd = proxyFlagCmd(t, so, "--ingest-proxy-host", "0.0.0.0")
	_, _, err = resolveIngestProxyAuth(cmd, so, &config.ServerConfig{})
	assert.NoError(t, err)

	// A malformed allow entry is a usage error too.
	so = &serverOptions{}
	cmd = proxyFlagCmd(t, so, "--proxy-allow", "10.0.0.0/99")
	_, _, err = resolveIngestProxyAuth(cmd, so, &config.ServerConfig{})
	require.Error(t, err)
	assert.Equal(t, 2, classifyExitCode(err))
}

// Config supplies host, token and allow-list when the flags are absent; the
// flags win when given.
func TestResolveIngestProxyAuthConfigFallback(t *testing.T) {
	sc := &config.ServerConfig{
		IngestProxyHost:  "0.0.0.0",
		IngestProxyToken: "from-config",
		IngestProxyAllow: []string{"10.0.0.0/8"},
	}
	so := &serverOptions{}
	cmd := proxyFlagCmd(t, so, "--ingest-proxy-port", "9003")
	host, auth, err := resolveIngestProxyAuth(cmd, so, sc)
	require.NoError(t, err)
	assert.Equal(t, "0.0.0.0", host)
	assert.Equal(t, "from-config", auth.Token)
	assert.Len(t, auth.Allow, 1)

	so = &serverOptions{}
	cmd = proxyFlagCmd(t, so, "--ingest-proxy-port", "9003", "--ingest-proxy-host", "127.0.0.1", "--proxy-token", "flag")
	host, auth, err = resolveIngestProxyAuth(cmd, so, sc)
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1", host)
	assert.Equal(t, "flag", auth.Token)
}

func TestIngestProxyDisplayURLHidesToken(t *testing.T) {
	so := &serverOptions{}
	cmd := proxyFlagCmd(t, so, "--proxy-token", "super-secret")
	_, auth, err := resolveIngestProxyAuth(cmd, so, &config.ServerConfig{})
	require.NoError(t, err)
	u := ingestProxyDisplayURL("127.0.0.1:9003", auth)
	assert.Equal(t, "http://vigolium:<proxy-token>@127.0.0.1:9003", u)
	assert.NotContains(t, u, "super-secret")
	assert.Equal(t, "http://127.0.0.1:9003", ingestProxyDisplayURL("127.0.0.1:9003", nil))
	assert.Equal(t, "[::1]:9003", joinHostPort("::1", 9003))
}

// The queue directory is keyed by the database: the same store maps to the
// same key however its path is spelled, and different stores never collide.
func TestServerQueueIdentity(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	a := serverQueueIdentity(&config.DatabaseConfig{Driver: "sqlite", SQLite: config.SQLiteConfig{Path: "~/.vigolium/db.sqlite"}})
	b := serverQueueIdentity(&config.DatabaseConfig{Driver: "sqlite", SQLite: config.SQLiteConfig{Path: "~/.vigolium/other.sqlite"}})
	pg := serverQueueIdentity(&config.DatabaseConfig{Driver: "postgres", Postgres: config.PostgresConfig{Host: "db", Port: 5432, User: "u", Database: "v"}})
	assert.NotEqual(t, a, b)
	assert.Equal(t, "postgres://u@db:5432/v", pg)
	assert.Contains(t, a, "sqlite:/")
}

// server and ingest both carry the hidden -S tombstone (A9), so `server -S`
// reaches rejectRetiredScanOnReceive instead of pflag's "unknown shorthand".
func TestServerAndIngestRejectRetiredS(t *testing.T) {
	for _, c := range []*cobra.Command{serverCmd, ingestCmd} {
		f := c.Flags().ShorthandLookup("S")
		require.NotNil(t, f, c.Name())
		assert.Equal(t, retiredScanOnReceiveFlag, f.Name)
		assert.True(t, f.Hidden)

		fs := pflag.NewFlagSet(c.Name(), pflag.ContinueOnError)
		var v bool
		fs.BoolVarP(&v, retiredScanOnReceiveFlag, "S", false, "")
		probe := &cobra.Command{Use: c.Name()}
		probe.Flags().AddFlagSet(fs)
		require.NoError(t, probe.Flags().Parse([]string{"-S"}))
		err := rejectRetiredScanOnReceive(probe)
		require.Error(t, err)
		assert.Equal(t, 2, classifyExitCode(err))
		assert.Contains(t, err.Error(), "--scan-on-receive")
		assert.Contains(t, err.Error(), c.Name())
	}
}
