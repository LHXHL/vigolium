package diagnostics

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/vigolium/vigolium/internal/config"
)

// checkScope runs the shared scope validator (the same rules `config set`
// enforces and `config validate` reports). An error-level issue is
// StatusError and degrades the verdict; warnings are StatusWarning.
func checkScope(settings *config.Settings) *CheckResult {
	issues := config.ValidateScope(settings.Scope)
	if len(issues) == 0 {
		return &CheckResult{Status: StatusOK, Message: "scope rules valid"}
	}
	res := &CheckResult{Status: StatusWarning}
	var nErr, nWarn int
	for _, is := range issues {
		if is.Severity == config.SeverityError {
			nErr++
		} else {
			nWarn++
		}
		line := is.Code + ": " + is.Message
		if is.Fix != "" {
			line += " (fix: " + is.Fix + ")"
		}
		res.Details = append(res.Details, line)
	}
	if nErr > 0 {
		res.Status = StatusError
		res.Message = fmt.Sprintf("%d error(s), %d warning(s) — scans drop requests the broken rules touch", nErr, nWarn)
	} else {
		res.Message = fmt.Sprintf("%d warning(s)", nWarn)
	}
	res.Tip = "run `vigolium config validate` for the full list with fixes"
	return res
}

// oastProbeTimeout bounds the whole OAST reachability probe (DNS + TLS).
const oastProbeTimeout = 3 * time.Second

// oastLookupHost and oastDialTLS are the network seams of the OAST probe,
// replaced in tests so they never touch the network.
var (
	oastLookupHost = func(ctx context.Context, host string) ([]string, error) {
		return net.DefaultResolver.LookupHost(ctx, host)
	}
	oastDialTLS = func(ctx context.Context, addr, serverName string) error {
		d := tls.Dialer{Config: &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12}}
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return err
		}
		return conn.Close()
	}
)

// checkOAST reports whether blind (out-of-band) checks will have a callback
// channel. It never registers with the server. The status does not affect the
// overall verdict: scans run without OAST and report oast_unavailable.
func checkOAST(settings *config.Settings, probe bool) *CheckResult {
	o := settings.OAST
	if !o.Enabled {
		return &CheckResult{
			Status:  StatusWarning,
			Message: "disabled — blind (out-of-band) checks will not run",
			Tip:     "enable with `vigolium config set oast.enabled true`",
		}
	}
	if fixed := strings.TrimSpace(o.OastURL); fixed != "" {
		return &CheckResult{Status: StatusOK, Message: "fixed callback URL " + fixed}
	}
	host, addr := oastServerAddr(o.ServerURL)
	if host == "" {
		return &CheckResult{
			Status:  StatusWarning,
			Message: "enabled with no oast.server_url or oast.oast_url",
			Tip:     oastUnavailableTip,
		}
	}
	if !probe {
		return &CheckResult{Status: StatusOK, Message: "interactsh server " + host + " (not probed)"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), oastProbeTimeout)
	defer cancel()
	if _, err := oastLookupHost(ctx, host); err != nil {
		return &CheckResult{
			Status:  StatusWarning,
			Message: "interactsh server " + host + " does not resolve",
			Details: []string{err.Error()},
			Tip:     oastUnavailableTip,
		}
	}
	if err := oastDialTLS(ctx, addr, host); err != nil {
		return &CheckResult{
			Status:  StatusWarning,
			Message: "interactsh server " + addr + " is not reachable over TLS",
			Details: []string{err.Error()},
			Tip:     oastUnavailableTip,
		}
	}
	return &CheckResult{Status: StatusOK, Message: "interactsh server " + addr + " reachable"}
}

const oastUnavailableTip = "OAST callbacks will be unavailable; set oast.oast_url or oast.enabled=false"

// oastServerAddr turns oast.server_url ("oast.pro", "https://oast.pro",
// "oast.example:8443") into the host to resolve and the host:port to dial.
func oastServerAddr(serverURL string) (host, addr string) {
	s := strings.TrimSpace(serverURL)
	if _, rest, ok := strings.Cut(s, "://"); ok {
		s = rest
	}
	s, _, _ = strings.Cut(s, "/")
	if s == "" {
		return "", ""
	}
	if h, port, err := net.SplitHostPort(s); err == nil {
		return h, net.JoinHostPort(h, port)
	}
	return s, net.JoinHostPort(s, "443")
}
