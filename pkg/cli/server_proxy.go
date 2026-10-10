package cli

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/queue"
	"github.com/vigolium/vigolium/pkg/server"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

// defaultServerHost is the REST API bind address. Loopback by default: the API
// can start scans and read every finding, so exposing it is an explicit choice
// (--host 0.0.0.0, or $VIGOLIUM_SERVER_HOST, which the Docker images set).
const defaultServerHost = "127.0.0.1"

// serverHostEnv overrides the --host default without a flag. The container
// images set it to 0.0.0.0, since a loopback bind is unreachable from outside
// a container.
const serverHostEnv = "VIGOLIUM_SERVER_HOST"

// serverQueueMaxAge is how old a task left in the disk-spill queue by a
// previous run may be and still be replayed.
const serverQueueMaxAge = 24 * time.Hour

// resolveServerHost applies $VIGOLIUM_SERVER_HOST when --host was not given.
func resolveServerHost(cmd *cobra.Command, flagValue string) string {
	if cmd.Flags().Changed("host") {
		return flagValue
	}
	if env := os.Getenv(serverHostEnv); env != "" {
		return env
	}
	return flagValue
}

// resolveIngestProxyAuth builds the ingest proxy's bind host and access
// control from flags with config fallback, and refuses (usage error, exit 2) a
// routable bind that has neither a token nor an allow-list.
func resolveIngestProxyAuth(cmd *cobra.Command, so *serverOptions, sc *config.ServerConfig) (string, *server.ProxyAuth, error) {
	host := so.IngestProxyHost
	if !cmd.Flags().Changed("ingest-proxy-host") && sc != nil && sc.IngestProxyHost != "" {
		host = sc.IngestProxyHost
	}
	token := so.ProxyToken
	if token == "" && sc != nil {
		token = sc.IngestProxyToken
	}
	allow := so.ProxyAllow
	if !cmd.Flags().Changed("proxy-allow") && sc != nil {
		allow = sc.IngestProxyAllow
	}
	auth, err := server.NewProxyAuth(token, allow)
	if err != nil {
		return "", nil, usageErrorf("%w", err)
	}
	if so.IngestProxyPort > 0 {
		if err := server.CheckProxyBind(host, auth); err != nil {
			return "", nil, usageErrorf("%w", err)
		}
	}
	return host, auth, nil
}

// ingestProxyDisplayURL is the proxy URL printed at startup. With a token it
// carries a credentials placeholder (never the token itself) so the line can
// be pasted into a client and filled in.
func ingestProxyDisplayURL(addr string, auth *server.ProxyAuth) string {
	if auth != nil && auth.Token != "" {
		return "http://vigolium:<proxy-token>@" + addr
	}
	return "http://" + addr
}

// joinHostPort renders host:port, bracketing IPv6 literals.
func joinHostPort(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// serverQueueRoot is where the durable scan-on-receive queues live.
func serverQueueRoot() string {
	return config.ExpandPath("~/.vigolium/server-queue")
}

// serverQueueIdentity names the database a server writes to, so the queue it
// spills to disk is found again by the next server on the same database and by
// no other.
func serverQueueIdentity(db *config.DatabaseConfig) string {
	if db == nil {
		return "default"
	}
	if db.Driver == "postgres" {
		p := db.Postgres
		return fmt.Sprintf("postgres://%s@%s:%d/%s", p.User, p.Host, p.Port, p.Database)
	}
	path := config.ExpandPath(db.SQLite.Path)
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	return "sqlite:" + path
}

// openServerQueue opens the durable scan-on-receive queue: a stable directory
// keyed by the database, locked for this process's lifetime, resumed when a
// previous run left tasks behind (dropping those older than 24h), and swept of
// the per-PID /tmp directories older versions leaked. The returned dir must be
// released after the queue is closed.
func openServerQueue(dbCfg *config.DatabaseConfig, memBuffer int, discard bool) (queue.Queue, *queue.ServerQueueDir, error) {
	root := serverQueueRoot()
	if n := queue.SweepLegacyServerQueues(os.TempDir(), root); n > 0 {
		zap.L().Info("Removed queue directories left by servers that are no longer running", zap.Int("count", n))
	}
	dir, err := queue.OpenServerQueueDir(root, serverQueueIdentity(dbCfg), discard)
	if err != nil {
		return nil, nil, err
	}
	if dir.Fallback && !globalSilent {
		fmt.Fprintf(os.Stderr, "%s another server holds the queue for this database; using %s for this run\n",
			terminal.WarnPrefix(), dir.Path)
	}
	q, err := queue.NewQueue(queue.Config{
		Type:             queue.QueueTypeHybrid,
		DiskDir:          dir.Path,
		MaxPerSegment:    10000,
		MemBufferSize:    memBuffer,
		DiscardOlderThan: serverQueueMaxAge,
	})
	if err != nil {
		dir.Release(false)
		return nil, nil, err
	}
	if r, ok := q.(interface{ RecoveredTasks() int64 }); ok {
		if n := r.RecoveredTasks(); n > 0 {
			zap.L().Info("Recovered queued tasks from the previous run",
				zap.Int64("tasks", n), zap.String("dir", dir.Path))
			if !globalSilent {
				fmt.Fprintf(os.Stderr, "%s recovered %d queued tasks from the previous run (older than %s are dropped; --discard-queued drops all)\n",
					terminal.InfoSymbol(), n, serverQueueMaxAge)
			}
		}
	}
	return q, dir, nil
}

// ingestProxyAuthLabel is the startup banner's one-word access-control label.
func ingestProxyAuthLabel(auth *server.ProxyAuth) string {
	switch {
	case !auth.Enabled():
		return "none (loopback only)"
	case auth.Token != "" && len(auth.Allow) > 0:
		return "token + allow-list"
	case auth.Token != "":
		return "token"
	default:
		return "allow-list"
	}
}

// closeServerQueue closes the task queue and releases its directory, removing
// the directory when nothing was left queued.
func closeServerQueue(q queue.Queue, dir *queue.ServerQueueDir) {
	empty := true
	if m := q.Metrics(); m != nil && m.Depth > 0 {
		empty = false
	}
	if err := q.Close(); err != nil {
		zap.L().Error("Queue close error", zap.Error(err))
	}
	dir.Release(empty)
}
