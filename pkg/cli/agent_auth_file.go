package cli

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/authentication"
	"github.com/vigolium/vigolium/pkg/database"
	vighttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
	"go.uber.org/zap"
)

// agent_auth_file.go gives the agent modes the native scan's --auth-file:
// the same session files, the same loader (authentication.LoadFromAuthFiles,
// bare names resolved against scanning_strategy.session.session_dir), the
// same --session-file alias, and the same validation before anything runs.

// authFileFlagUsage is --auth-file's help on the agent commands.
const authFileFlagUsage = "Native session file, as 'vigolium scan --auth-file' takes (YAML/JSON, single session or sessions: bundle; login flows, steps, OAuth2, check/reauth), or a bare name resolved against scanning_strategy.session.session_dir. Repeatable; commas are literal."

// authFileAliases spells --auth-file as --session-file, the former name the
// scan commands still accept, so a command copied from an older guide works.
var authFileAliases = map[string]string{"session-file": "auth-file"}

// agentAuthSource is the authentication an agent run was given up front.
type agentAuthSource struct {
	// Path is the session file the run's native phases load (their
	// --auth-file).
	Path string
	// Config is the agent-format view of the sessions (static headers for
	// recon, prompt artifacts). Nil for an agent-format --auth-config.
	Config *agent.AgentSessionConfig
	// Sessions are the loaded native sessions. Nil for an agent-format
	// --auth-config.
	Sessions []*authentication.Session
}

// loadAgentAuthFiles loads and validates --auth-file values exactly as a
// native scan does, so a file that scans also works here (and a broken one
// fails before the run starts, not in its scan phase).
func loadAgentAuthFiles(settings *config.Settings, files []string) ([]*authentication.Session, error) {
	sessions, err := authentication.LoadFromAuthFiles(files, authSessionDir(settings))
	if err != nil {
		return nil, codedErrorf(apicontract.CodeConfigInvalid, "%w", err)
	}
	for _, s := range sessions {
		if err := s.Validate(); err != nil {
			return nil, codedErrorf(apicontract.CodeConfigInvalid, "auth file: %w", err)
		}
	}
	return sessions, nil
}

func authSessionDir(settings *config.Settings) string {
	if settings == nil {
		return ""
	}
	return settings.ScanningStrategy.Session.SessionDir
}

// resolveSwarmAuth resolves swarm's --auth-file / --auth-config into the
// session file its native phases load. nil means neither was given.
//
// --auth-file values are validated, and one file is used as is; several are
// merged into <sessionDir>/auth-config.yaml, losslessly (native format).
// --auth-config keeps taking an agent auth-config verbatim; a native session
// file given there is detected and handled as --auth-file.
func resolveSwarmAuth(settings *config.Settings, authFiles []string, authConfig, sessionDir string) (*agentAuthSource, error) {
	if len(authFiles) > 0 && authConfig != "" {
		return nil, usageErrorf("--auth-file and --auth-config are mutually exclusive (--auth-file takes native session files, --auth-config an agent auth-config)")
	}
	if authConfig != "" {
		data, err := os.ReadFile(authConfig)
		if err != nil {
			return nil, codedErrorf(apicontract.CodeConfigInvalid, "auth config: %w", err)
		}
		doc, err := authentication.ParseSessionDocument(data, authConfig, authentication.ParseOptions{})
		if err != nil || doc.Form == authentication.FormAgent || len(doc.Sessions) == 0 {
			zap.L().Info("Using operator-supplied auth-config", zap.String("path", authConfig))
			return &agentAuthSource{Path: authConfig}, nil
		}
		fmt.Fprintf(os.Stderr, "%s --auth-config %s is a native session file; loading it as --auth-file\n",
			terminal.InfoSymbol(), terminal.ShortenHome(authConfig))
		authFiles = []string{authConfig}
	}
	if len(authFiles) == 0 {
		return nil, nil
	}

	sessions, err := loadAgentAuthFiles(settings, authFiles)
	if err != nil {
		return nil, err
	}
	src := &agentAuthSource{Sessions: sessions, Config: agent.SessionsToAgentSessionConfig(sessions)}
	if len(authFiles) == 1 {
		src.Path = authentication.ResolveSessionPath(authFiles[0], authSessionDir(settings))
	} else {
		// Re-read without expanding ${ENV}: the merged file is expanded once,
		// when the native phase loads it.
		var raw []*authentication.Session
		for _, f := range authFiles {
			path := authentication.ResolveSessionPath(f, authSessionDir(settings))
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, codedErrorf(apicontract.CodeConfigInvalid, "auth file: %w", err)
			}
			loaded, _, err := authentication.ParseSessionBytes(data, path, authentication.ParseOptions{KeepEnvRefs: true})
			if err != nil {
				return nil, codedErrorf(apicontract.CodeConfigInvalid, "auth file: %w", err)
			}
			raw = append(raw, loaded...)
		}
		if src.Path, err = agent.WriteSessionsAuthConfigYAML(sessionDir, raw); err != nil {
			return nil, fmt.Errorf("merge %d auth files: %w", len(authFiles), err)
		}
	}
	zap.L().Info("Using --auth-file sessions",
		zap.String("path", src.Path), zap.Int("files", len(authFiles)), zap.Int("sessions", len(sessions)))
	return src, nil
}

// prepareAutopilotAuthFiles logs autopilot's --auth-file sessions in before
// the run and stores them (with the credentials they earned) for the target's
// hostname in the project, where the operator's list_auth_sessions and
// replay_request tools read them. The native pre-scan loads the same files
// itself. A login that fails stops the run: an explicit auth file that does
// not authenticate is an error, as it is for `vigolium scan --auth-file`.
// With login false (--dry-run) the files are only loaded and validated.
func prepareAutopilotAuthFiles(ctx context.Context, settings *config.Settings, repo *database.Repository, projectUUID, target string, files []string, login bool) error {
	if len(files) == 0 {
		return nil
	}
	sessions, err := loadAgentAuthFiles(settings, files)
	if err != nil || !login {
		return err
	}
	mgr, err := authentication.NewManager(sessions,
		authentication.WithSessionDir(authSessionDir(settings)),
		authentication.WithLoginTransport(vighttp.LoginTransport(&types.Options{ProxyURL: globalProxy})),
	)
	if err != nil {
		return codedErrorf(apicontract.CodeConfigInvalid, "auth file: %w", err)
	}
	if err := mgr.HydrateSessionsContext(ctx); err != nil {
		return codedErrorf(apicontract.CodeLoginFailed, "auth file login failed: %w", err)
	}

	stored := ""
	if u, perr := url.Parse(target); perr == nil && u.Hostname() != "" && repo != nil && projectUUID != "" {
		now := time.Now().UTC()
		rows := database.SessionsToAuthenticationHostnames(mgr.AllSessions(), projectUUID, u.Hostname())
		for _, row := range rows {
			row.HydratedAt = &now
		}
		if err := repo.SaveAuthenticationHostnames(ctx, rows); err != nil {
			return fmt.Errorf("store auth-file sessions: %w", err)
		}
		stored = " and stored for " + u.Hostname()
	}
	fmt.Fprintf(os.Stderr, "%s --auth-file: %d session(s) logged in%s\n",
		terminal.SuccessSymbol(), len(sessions), stored)
	return nil
}
