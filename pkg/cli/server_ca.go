package cli

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/server/mitm"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// `vigolium server ca …` manages the ingest proxy's MITM CA: where it is, what
// it is, and how to make this machine trust it. The CA is created on first use
// (the same load-or-create the running proxy does), so every subcommand works
// before the server has ever started.

var (
	serverCAOut string
	serverCAYes bool
)

var serverCACmd = &cobra.Command{
	Use:   "ca",
	Short: "Show, export and trust the ingest-proxy MITM CA certificate",
	Long: `Manage the CA the ingest proxy uses to intercept HTTPS (--proxy-mitm).

  print      PEM to stdout (or --out FILE); -j gives path, sha256, subject, not_after
  path       where the certificate lives
  install    print the commands that trust it on this OS; --yes runs them
  uninstall  print the commands that remove that trust; --yes runs them`,
	Args: cobra.NoArgs,
}

var serverCAPrintCmd = &cobra.Command{
	Use:   "print",
	Short: "Print the MITM CA certificate (PEM), or write it with --out",
	Args:  cobra.NoArgs,
	RunE:  runServerCAPrint,
}

var serverCAPathCmd = &cobra.Command{
	Use:   "path",
	Short: "Print the path of the MITM CA certificate",
	Args:  cobra.NoArgs,
	RunE:  runServerCAPath,
}

var serverCAInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Trust the MITM CA on this machine (prints the commands; --yes runs them)",
	Args:  cobra.NoArgs,
	RunE:  func(cmd *cobra.Command, _ []string) error { return runServerCATrust(cmd, caActionInstall) },
}

var serverCAUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Remove trust in the MITM CA (prints the commands; --yes runs them)",
	Args:  cobra.NoArgs,
	RunE:  func(cmd *cobra.Command, _ []string) error { return runServerCATrust(cmd, caActionUninstall) },
}

func init() {
	serverCmd.AddCommand(serverCACmd)
	serverCACmd.AddCommand(serverCAPrintCmd, serverCAPathCmd, serverCAInstallCmd, serverCAUninstallCmd)
	serverCAPrintCmd.Flags().StringVar(&serverCAOut, "out", "", "Write the PEM certificate to this file instead of stdout")
	for _, c := range []*cobra.Command{serverCAInstallCmd, serverCAUninstallCmd} {
		c.Flags().BoolVar(&serverCAYes, "yes", false, "Run the commands instead of printing them (may prompt for sudo)")
	}
}

// caCertInfo is `server ca print -j`'s object.
type caCertInfo struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	Subject   string `json:"subject"`
	NotAfter  string `json:"not_after"`
	WrittenTo string `json:"written_to,omitempty"`
}

// loadProxyCACert loads (creating on first use) the MITM CA and parses its
// certificate.
func loadProxyCACert() (path string, pemBytes []byte, cert *x509.Certificate, err error) {
	ca, err := mitm.LoadOrCreateCA(proxyCADir())
	if err != nil {
		return "", nil, nil, fmt.Errorf("initialize MITM CA: %w", err)
	}
	path = ca.CertPath()
	pemBytes, err = os.ReadFile(path)
	if err != nil {
		return "", nil, nil, err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", nil, nil, fmt.Errorf("%s holds no PEM certificate", path)
	}
	cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", nil, nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return path, pemBytes, cert, nil
}

func newCACertInfo(path string, cert *x509.Certificate) caCertInfo {
	sum := sha256.Sum256(cert.Raw)
	return caCertInfo{
		Path:     path,
		SHA256:   hex.EncodeToString(sum[:]),
		Subject:  cert.Subject.String(),
		NotAfter: cert.NotAfter.UTC().Format(time.RFC3339),
	}
}

func runServerCAPrint(cmd *cobra.Command, _ []string) error {
	path, pemBytes, cert, err := loadProxyCACert()
	if err != nil {
		return err
	}
	info := newCACertInfo(path, cert)
	if serverCAOut != "" {
		dst := config.ExpandPath(serverCAOut)
		if err := os.WriteFile(dst, pemBytes, 0o644); err != nil {
			return fmt.Errorf("write CA certificate: %w", err)
		}
		info.WrittenTo = dst
	}
	if globalJSON {
		return emitObject(cmd, "", info)
	}
	if serverCAOut == "" {
		_, err := os.Stdout.Write(pemBytes)
		return err
	}
	if !globalSilent {
		fmt.Printf("%s Ingest-proxy CA certificate written to %s\n", terminal.InfoSymbol(), terminal.Cyan(info.WrittenTo))
		fmt.Printf("  sha256 %s\n  Trust it with: vigolium server ca install\n", info.SHA256)
	}
	return nil
}

func runServerCAPath(cmd *cobra.Command, _ []string) error {
	path, _, _, err := loadProxyCACert()
	if err != nil {
		return err
	}
	if globalJSON {
		return emitObject(cmd, "", map[string]string{"path": path})
	}
	fmt.Println(path)
	return nil
}

const (
	caActionInstall   = "install"
	caActionUninstall = "uninstall"
)

// caTrustStep is one command of a trust plan.
type caTrustStep struct {
	Argv []string `json:"argv"`
}

// caTrustPlan is what install/uninstall would run on one platform. Notes are
// manual follow-ups (browsers with their own trust store) that --yes never runs.
type caTrustPlan struct {
	Platform string        `json:"platform"`
	Steps    []caTrustStep `json:"steps"`
	Notes    []string      `json:"notes,omitempty"`
}

// Linux trust-store families, by the tool that rebuilds the bundle.
const (
	linuxFamilyDebian = "debian" // update-ca-certificates
	linuxFamilyRHEL   = "rhel"   // update-ca-trust
)

// buildCATrustPlan is the pure command builder behind install/uninstall:
// everything platform-specific is a parameter, so it is table-tested for every
// OS from any OS. home is the user's home directory, commonName the CA's CN
// (how macOS and Windows find it again to remove it), and root whether the
// process already runs as root (Linux steps get sudo otherwise).
func buildCATrustPlan(goos, linuxFamily, action, certPath, home, commonName string, root bool) (caTrustPlan, error) {
	if action != caActionInstall && action != caActionUninstall {
		return caTrustPlan{}, fmt.Errorf("unknown CA action %q", action)
	}
	install := action == caActionInstall
	sudo := func(argv ...string) caTrustStep {
		if root {
			return caTrustStep{Argv: argv}
		}
		return caTrustStep{Argv: append([]string{"sudo"}, argv...)}
	}
	nssDB := "sql:" + filepath.Join(home, ".pki", "nssdb")
	nssNote := fmt.Sprintf("Firefox keeps its own store: import %s under Settings → Privacy & Security → Certificates, "+
		"or set security.enterprise_roots.enabled=true to make it honour the OS store", certPath)

	switch goos {
	case "darwin":
		keychain := filepath.Join(home, "Library", "Keychains", "login.keychain-db")
		plan := caTrustPlan{Platform: "macos", Notes: []string{nssNote}}
		if install {
			plan.Steps = []caTrustStep{{Argv: []string{"security", "add-trusted-cert", "-r", "trustRoot", "-k", keychain, certPath}}}
		} else {
			plan.Steps = []caTrustStep{
				{Argv: []string{"security", "remove-trusted-cert", certPath}},
				{Argv: []string{"security", "delete-certificate", "-c", commonName, keychain}},
			}
		}
		return plan, nil

	case "windows":
		plan := caTrustPlan{Platform: "windows", Notes: []string{nssNote}}
		if install {
			plan.Steps = []caTrustStep{{Argv: []string{"certutil", "-user", "-addstore", "Root", certPath}}}
		} else {
			plan.Steps = []caTrustStep{{Argv: []string{"certutil", "-user", "-delstore", "Root", commonName}}}
		}
		return plan, nil

	case "linux":
		var nss string
		if install {
			nss = fmt.Sprintf("Chrome/Chromium on Linux read the NSS store: certutil -d %s -A -t C,, -n %q -i %s", nssDB, commonName, certPath)
		} else {
			nss = fmt.Sprintf("Chrome/Chromium on Linux read the NSS store: certutil -d %s -D -n %q", nssDB, commonName)
		}
		notes := []string{nss, nssNote}
		switch linuxFamily {
		case linuxFamilyDebian:
			dst := "/usr/local/share/ca-certificates/vigolium.crt"
			plan := caTrustPlan{Platform: "linux-debian", Notes: notes}
			if install {
				plan.Steps = []caTrustStep{sudo("cp", certPath, dst), sudo("update-ca-certificates")}
			} else {
				plan.Steps = []caTrustStep{sudo("rm", "-f", dst), sudo("update-ca-certificates", "--fresh")}
			}
			return plan, nil
		case linuxFamilyRHEL:
			dst := "/etc/pki/ca-trust/source/anchors/vigolium.pem"
			plan := caTrustPlan{Platform: "linux-rhel", Notes: notes}
			if install {
				plan.Steps = []caTrustStep{sudo("cp", certPath, dst), sudo("update-ca-trust")}
			} else {
				plan.Steps = []caTrustStep{sudo("rm", "-f", dst), sudo("update-ca-trust")}
			}
			return plan, nil
		default:
			return caTrustPlan{Platform: "linux", Notes: append([]string{
				"unrecognised trust store (neither update-ca-certificates nor update-ca-trust found): " +
					"add " + certPath + " to your distribution's CA bundle by hand",
			}, notes...)}, nil
		}
	}
	return caTrustPlan{Platform: goos, Notes: []string{
		"no trust-store recipe for " + goos + ": add " + certPath + " to the system or browser trust store by hand",
	}}, nil
}

// detectLinuxFamily picks the trust-store tooling present on this host.
func detectLinuxFamily() string {
	if _, err := exec.LookPath("update-ca-certificates"); err == nil {
		return linuxFamilyDebian
	}
	if _, err := exec.LookPath("update-ca-trust"); err == nil {
		return linuxFamilyRHEL
	}
	return ""
}

func runServerCATrust(cmd *cobra.Command, action string) error {
	path, _, cert, err := loadProxyCACert()
	if err != nil {
		return err
	}
	home, _ := os.UserHomeDir()
	family := ""
	if runtime.GOOS == "linux" {
		family = detectLinuxFamily()
	}
	plan, err := buildCATrustPlan(runtime.GOOS, family, action, path, home, cert.Subject.CommonName, os.Geteuid() == 0)
	if err != nil {
		return err
	}

	if serverCAYes {
		if len(plan.Steps) == 0 {
			return fmt.Errorf("no %s commands for %s: %s", action, plan.Platform, strings.Join(plan.Notes, "; "))
		}
		// Child output goes to stderr under -j so stdout stays one document.
		var out io.Writer = os.Stdout
		if globalJSON {
			out = os.Stderr
		}
		for _, step := range plan.Steps {
			if !globalJSON && !globalSilent {
				fmt.Fprintf(os.Stderr, "%s %s\n", terminal.InfoSymbol(), shellJoin(step.Argv))
			}
			c := exec.Command(step.Argv[0], step.Argv[1:]...)
			c.Stdin, c.Stdout, c.Stderr = os.Stdin, out, os.Stderr
			if err := c.Run(); err != nil {
				var exitErr *exec.ExitError
				if errors.As(err, &exitErr) {
					return fmt.Errorf("%s failed (exit %d)", shellJoin(step.Argv), exitErr.ExitCode())
				}
				return fmt.Errorf("%s: %w", shellJoin(step.Argv), err)
			}
		}
	}

	if globalJSON {
		return emitMutation(cmd, "", mutationResult{
			Changed: serverCAYes,
			Action:  action,
			DryRun:  !serverCAYes,
			Items:   plan.Steps,
			Extra:   map[string]any{"platform": plan.Platform, "cert_path": path, "notes": plan.Notes},
		})
	}
	if serverCAYes {
		if !globalSilent {
			fmt.Printf("%s CA %s complete (%s)\n", terminal.InfoSymbol(), action, plan.Platform)
		}
	} else if len(plan.Steps) > 0 {
		fmt.Printf("# %s the Vigolium ingest-proxy CA (%s); rerun with --yes to execute:\n", action, plan.Platform)
		for _, step := range plan.Steps {
			fmt.Println(shellJoin(step.Argv))
		}
	}
	for _, n := range plan.Notes {
		fmt.Printf("# note: %s\n", n)
	}
	return nil
}

// shellSafeRune reports whether r needs no quoting in a POSIX shell word.
func shellSafeRune(r rune) bool {
	return r == '-' || r == '_' || r == '.' || r == '/' || r == ':' || r == ',' || r == '=' || r == '@' ||
		(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}

// shellJoin renders argv for copy-paste into a POSIX shell, single-quoting any
// argument that is not plainly safe.
func shellJoin(argv []string) string {
	parts := make([]string, len(argv))
	for i, a := range argv {
		if a != "" && strings.IndexFunc(a, func(r rune) bool { return !shellSafeRune(r) }) < 0 {
			parts[i] = a
			continue
		}
		parts[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
	}
	return strings.Join(parts, " ")
}
