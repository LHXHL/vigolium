package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/atomicfile"
	"github.com/vigolium/vigolium/pkg/deparos/jstangle"
	"github.com/vigolium/vigolium/pkg/harvester"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var (
	kitBeautifyExtract       bool
	kitBeautifyTimeout       time.Duration
	kitBeautifyOutput        string
	kitBeautifyModulesDir    string
	kitBeautifyProfile       string
	kitBeautifyUnpackModules bool
	kitBeautifyMaxASTNodes   int
	kitBeautifyMaxInputMB    int
	kitBeautifyDeadline      time.Duration
)

var kitJSBeautifyCmd = &cobra.Command{
	Use:   "js-beautify [file|url|-]",
	Short: "Unminify and unpack a JavaScript bundle into readable source",
	Long: `Unminify + unpack minified/bundled JavaScript into readable source using the
embedded jstangle tool (webcrack — unminify and bundle-unpack, no eval-based
deobfuscation). The argument is a local file, an http(s):// URL (fetched), or
'-'/no argument for stdin.

  vigolium kit js-beautify app.min.js                     # local file
  vigolium kit js-beautify https://acme.test/main.abc.js  # fetch + beautify
  cat bundle.js | vigolium kit js-beautify -              # stdin
  vigolium kit js-beautify -o app.js app.min.js           # write to a file
  vigolium kit js-beautify --modules ./out app.min.js     # one file per module
  vigolium kit js-beautify -j --extract app.min.js        # + extracted endpoints

By default the beautified source is written to stdout. If the input is neither
minified nor bundled it is emitted unchanged (a note goes to stderr). --extract
also runs endpoint extraction and, with -j, includes discovered requests.

A bundle of several hundred modules is far more useful as a directory than as
one document: --modules writes each recovered module to its own file under the
given directory, at its recovered path.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runKitJSBeautify,
}

func init() {
	f := kitJSBeautifyCmd.Flags()
	f.BoolVar(&kitBeautifyExtract, "extract", false, "Also extract endpoints/requests (a full analysis pass); included in -j output")
	f.DurationVar(&kitBeautifyTimeout, "timeout", 30*time.Second, "Timeout for fetching a URL argument")
	f.StringVarP(&kitBeautifyOutput, "output", "o", "", "Write the beautified source to this file instead of stdout")
	f.StringVar(&kitBeautifyModulesDir, "modules", "", "Write each recovered bundle module to its own file under this directory")
	f.StringVar(&kitBeautifyProfile, "profile", "", "Analysis profile ("+strings.Join(kitBeautifyProfileNames(), ", ")+"); default depends on --extract")
	f.BoolVar(&kitBeautifyUnpackModules, "unpack-modules", false, "Unpack a detected bundle and re-scan each module for endpoints (implies --extract)")
	f.IntVar(&kitBeautifyMaxASTNodes, "max-ast-nodes", 0, "Maximum parsed AST nodes before the analysis degrades to a per-module scan (0 = engine default)")
	f.IntVar(&kitBeautifyMaxInputMB, "max-input-mb", 0, "Lower the input size limit, in MiB; cannot raise it above the service ceiling (0 = engine default)")
	f.DurationVar(&kitBeautifyDeadline, "deadline", 0, "Analysis deadline (0 = engine default)")
	kitCmd.AddCommand(kitJSBeautifyCmd)
}

type kitBeautifyResult struct {
	Source string `json:"source"`
	// Status is the engine's own verdict: complete, partial, or failed. Without
	// it, output from a clean AST pass and from the degraded string fallback are
	// identical in shape, and a programmatic caller cannot tell them apart.
	Status         string                `json:"status,omitempty"`
	Changed        bool                  `json:"changed"`
	Format         string                `json:"format,omitempty"`
	ModuleCount    int                   `json:"module_count"`
	ModulePaths    []string              `json:"module_paths,omitempty"`
	BytesIn        int                   `json:"bytes_in"`
	BytesOut       int                   `json:"bytes_out"`
	Content        string                `json:"content"`
	Endpoints      []kitBeautifyEndpoint `json:"endpoints,omitempty"`
	Diagnostics    []jstangle.Diagnostic `json:"diagnostics,omitempty"`
	OutputPath     string                `json:"output_path,omitempty"`
	ModulesDir     string                `json:"modules_dir,omitempty"`
	ModulesWritten int                   `json:"modules_written,omitempty"`
}

// kitBeautifyEndpoint is the legacy flat request plus the provenance the typed
// fact carries. ExtractedRequest alone cannot say whether a method was resolved
// from the AST or guessed by a regex, which is the difference that decides
// whether a downstream planner should replay it.
type kitBeautifyEndpoint struct {
	jstangle.ExtractedRequest
	Extractor  string `json:"extractor,omitempty"`
	Confidence string `json:"confidence,omitempty"`
	ModulePath string `json:"module_path,omitempty"`
}

// kitBeautifyEndpoints prefers the typed facts (which carry provenance) and
// falls back to the flat legacy list when a backend produced only that.
func kitBeautifyEndpoints(res *jstangle.ScanResult) []kitBeautifyEndpoint {
	if res == nil {
		return nil
	}
	if len(res.RequestFacts) > 0 {
		endpoints := make([]kitBeautifyEndpoint, 0, len(res.RequestFacts))
		for i := range res.RequestFacts {
			fact := res.RequestFacts[i]
			endpoints = append(endpoints, kitBeautifyEndpoint{
				ExtractedRequest: jstangle.LegacyRequestFromFact(fact),
				Extractor:        fact.Provenance.Extractor,
				Confidence:       fact.Provenance.Confidence,
				ModulePath:       fact.Provenance.ModulePath,
			})
		}
		return endpoints
	}
	endpoints := make([]kitBeautifyEndpoint, 0, len(res.Requests))
	for _, request := range res.Requests {
		endpoints = append(endpoints, kitBeautifyEndpoint{ExtractedRequest: request})
	}
	return endpoints
}

func runKitJSBeautify(cmd *cobra.Command, args []string) error {
	arg := "-"
	if len(args) == 1 {
		arg = args[0]
	}

	data, label, mediaType, err := kitResolveJSInput(arg)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return fmt.Errorf("no input: %s is empty", label)
	}

	service, err := jstangle.DefaultService()
	if err != nil {
		return fmt.Errorf("jstangle unavailable (embedded binary missing or unsupported platform): %w", err)
	}

	// --unpack-modules only means anything alongside endpoint extraction.
	extract := kitBeautifyExtract || kitBeautifyUnpackModules
	// An over-budget bundle can return endpoints even under the plain beautify
	// profile (the engine's per-module rescue), so this guard is load-bearing.
	withEndpoints := extract || kitBeautifyProfile != ""

	// Resolve the profile once: an explicit --profile wins, otherwise --extract
	// asks for the full pass, otherwise beautify alone. Mutating opts in sequence
	// left Beautify set differently for --profile beautify and the default, which
	// split the service cache key across two entries for identical work.
	profile, beautify := jstangle.ProfileBeautify, false
	if extract {
		profile, beautify = jstangle.ProfileFull, true
	}
	if kitBeautifyProfile != "" {
		profile = jstangle.AnalysisProfile(kitBeautifyProfile)
		if !kitBeautifyProfileKnown(profile) {
			return fmt.Errorf("unknown profile %q (want one of: %s)", kitBeautifyProfile,
				strings.Join(kitBeautifyProfileNames(), ", "))
		}
		beautify = true
	}
	opts := jstangle.ScanOptions{
		Profile:       profile,
		Beautify:      beautify,
		SourceURL:     label,
		Filename:      filepath.Base(label),
		MediaType:     mediaType,
		UnpackModules: kitBeautifyUnpackModules,
		MaxASTNodes:   kitBeautifyMaxASTNodes,
		Deadline:      kitBeautifyDeadline,
	}
	if kitBeautifyMaxInputMB > 0 {
		opts.MaxInputBytes = kitBeautifyMaxInputMB * 1024 * 1024
	}

	ctx := context.Background()
	res, scanErr := service.ScanWithOptions(ctx, data, opts)
	if scanErr != nil {
		if errors.Is(scanErr, jstangle.ErrUnsupportedProfile) {
			return fmt.Errorf("the embedded jstangle binary does not support the %q profile; update the binary", opts.Profile)
		}
		return fmt.Errorf("beautify failed: %w", scanErr)
	}

	result := kitBeautifyResult{Source: label, BytesIn: len(data), Content: string(data)}
	if res != nil {
		result.Status = res.Status()
		result.Diagnostics = res.Diagnostics
	}
	if res != nil && res.HasBeautified() {
		b := res.Beautified
		result.Changed = true
		result.Format = b.Format
		result.ModuleCount = b.ModuleCount
		result.ModulePaths = b.ModulePaths
		result.Content = b.Content
	}
	result.BytesOut = len(result.Content)
	if withEndpoints {
		result.Endpoints = kitBeautifyEndpoints(res)
	}

	if kitBeautifyModulesDir != "" {
		written, werr := kitWriteBeautifiedModules(kitBeautifyModulesDir, res, label, result.Content)
		if werr != nil {
			return werr
		}
		result.ModulesDir = kitBeautifyModulesDir
		result.ModulesWritten = written
	}
	if dest := kitBeautifyOutputDestination(); dest != "" {
		if werr := atomicfile.WriteBytes(dest, []byte(result.Content)); werr != nil {
			return fmt.Errorf("writing %s: %w", dest, werr)
		}
		result.OutputPath = dest
	}

	if globalJSON {
		return writeAgentJSON(result)
	}

	// Plain mode: the beautified (or unchanged) source is the payload on stdout;
	// status notes go to stderr so a pipe stays clean.
	if !result.Changed {
		fmt.Fprintf(os.Stderr, "%s %s\n", terminal.InfoSymbol(), kitBeautifyUnchangedReason(label, res))
	} else {
		fmt.Fprintf(os.Stderr, "%s beautified %s (%s, %d module(s), %d → %d bytes)\n",
			terminal.InfoSymbol(), label, result.Format, result.ModuleCount, result.BytesIn, result.BytesOut)
	}
	if result.ModulesWritten > 0 {
		fmt.Fprintf(os.Stderr, "%s wrote %d module(s) to %s\n",
			terminal.InfoSymbol(), result.ModulesWritten, result.ModulesDir)
	}
	if result.OutputPath != "" {
		fmt.Fprintf(os.Stderr, "%s wrote %d bytes to %s\n",
			terminal.InfoSymbol(), result.BytesOut, result.OutputPath)
	}
	// Only fall back to stdout when the source was not already written somewhere.
	// Gated on what was asked for, not on how it turned out: a --modules run whose
	// paths were all rejected must not also dump the document to stdout.
	if kitBeautifyOutputDestination() == "" && kitBeautifyModulesDir == "" {
		fmt.Print(result.Content)
		if !strings.HasSuffix(result.Content, "\n") {
			fmt.Println()
		}
	}
	if len(result.Endpoints) > 0 {
		fmt.Fprintf(os.Stderr, "\n%s %d endpoint(s) extracted:\n", terminal.InfoSymbol(), len(result.Endpoints))
		for _, endpoint := range result.Endpoints {
			method := endpoint.Method
			if method == "" {
				method = "?" // unresolved, not a guess
			}
			line := fmt.Sprintf("  %-6s %s", method, endpoint.URL)
			if endpoint.ModulePath != "" {
				line += "  (" + endpoint.ModulePath + ")"
			}
			if endpoint.Confidence != "" {
				line += "  [" + endpoint.Confidence + "]"
			}
			fmt.Fprintln(os.Stderr, line)
		}
	}
	return nil
}

var kitBeautifyProfiles = []jstangle.AnalysisProfile{
	jstangle.ProfileBeautify, jstangle.ProfileEndpoints, jstangle.ProfileDiscovery,
	jstangle.ProfileDiscoveryLite, jstangle.ProfileFull, jstangle.ProfileInspect,
	jstangle.ProfileDOMSecurity, jstangle.ProfileLegacy,
}

// kitBeautifyOutputDestination returns the file the beautified source should go
// to, or "" for stdout. "-" means stdout, matching the repo's other -o flags.
func kitBeautifyOutputDestination() string {
	dest := strings.TrimSpace(kitBeautifyOutput)
	if dest == "-" {
		return ""
	}
	return dest
}

func kitBeautifyProfileKnown(profile jstangle.AnalysisProfile) bool {
	for _, known := range kitBeautifyProfiles {
		if profile == known {
			return true
		}
	}
	return false
}

func kitBeautifyProfileNames() []string {
	names := make([]string, 0, len(kitBeautifyProfiles))
	for _, profile := range kitBeautifyProfiles {
		names = append(names, string(profile))
	}
	return names
}

// kitWriteBeautifiedModules writes each recovered module to its own file under
// dir, at its recovered path. When the document is not a bundle (or cannot be
// split) the whole document is written as a single file instead, so the flag
// always produces something usable.
//
// Module paths come out of webcrack and are derived from bundle metadata, so
// they are attacker-influenced: every path is confined to dir before any write.
func kitWriteBeautifiedModules(dir string, res *jstangle.ScanResult, label, content string) (int, error) {
	root, err := filepath.Abs(dir)
	if err != nil {
		return 0, fmt.Errorf("resolving %s: %w", dir, err)
	}
	if err := os.MkdirAll(root, 0o750); err != nil {
		return 0, fmt.Errorf("creating %s: %w", dir, err)
	}

	var modules []jstangle.BeautifiedModule
	if res != nil {
		modules = res.Beautified.Modules()
	}
	if len(modules) == 0 {
		name := filepath.Base(label)
		if name == "" || name == "." || name == string(filepath.Separator) {
			name = "source.js"
		}
		modules = []jstangle.BeautifiedModule{{Path: name, Content: content}}
	}

	written := 0
	for _, module := range modules {
		target, ok := kitSafeModulePath(root, module.Path)
		if !ok {
			fmt.Fprintf(os.Stderr, "%s skipped module with unsafe path %q\n", terminal.WarningSymbol(), module.Path)
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
			return written, fmt.Errorf("creating %s: %w", filepath.Dir(target), err)
		}
		if err := atomicfile.WriteBytes(target, []byte(module.Content)); err != nil {
			return written, fmt.Errorf("writing %s: %w", target, err)
		}
		written++
	}
	return written, nil
}

// kitSafeModulePath resolves a recovered module path strictly beneath root.
// Returns the cleaned absolute target and whether it is safe to write.
//
// A leading "/" covers a Unix absolute path and, after ToSlash on Windows, a
// UNC path; a volume prefix is caught by the colon. Backslashes are rejected
// outright because ToSlash is a no-op on Unix, where they would otherwise
// survive as literal characters in a filename. The containment test is
// deliberately strict about root itself: "." and "a/.." both Join back to root,
// and appending an extension to that writes a sibling of the output directory.
func kitSafeModulePath(root, modulePath string) (string, bool) {
	cleaned := strings.TrimPrefix(filepath.ToSlash(modulePath), "./")
	if cleaned == "" || strings.HasPrefix(cleaned, "/") ||
		strings.Contains(cleaned, ":") || strings.Contains(cleaned, `\`) {
		return "", false
	}
	target := filepath.Join(root, filepath.FromSlash(cleaned))
	if !strings.HasPrefix(target, root+string(filepath.Separator)) {
		return "", false
	}
	switch filepath.Ext(target) {
	case ".js", ".mjs", ".cjs", ".ts":
	default:
		target += ".js"
	}
	return target, true
}

// kitBeautifyUnchangedReason explains why nothing came back. Three distinct
// outcomes used to collapse into "neither minified nor bundled": a script that
// genuinely is not a bundle, an analysis that ran and failed, and an input the
// service refused to dispatch at all. Only the first of those is a property of
// the script, and reporting the other two as if they were is how an oversized
// bundle looks like a plain file.
func kitBeautifyUnchangedReason(label string, res *jstangle.ScanResult) string {
	if res != nil {
		for _, diagnostic := range res.Diagnostics {
			if diagnostic.Stage == "admission" {
				return fmt.Sprintf("%s was not analyzed (%s) — emitted unchanged", label, diagnostic.Code)
			}
		}
		if status := res.Status(); status == "failed" || status == "partial" {
			code := ""
			if res.Completion != nil {
				code = res.Completion.ReasonCode
			}
			if code == "" && len(res.Diagnostics) > 0 {
				code = res.Diagnostics[len(res.Diagnostics)-1].Code
			}
			if code != "" {
				return fmt.Sprintf("%s analysis did not complete (%s) — emitted unchanged", label, code)
			}
			return fmt.Sprintf("%s analysis did not complete — emitted unchanged", label)
		}
	}
	return fmt.Sprintf("%s is neither minified nor bundled — emitted unchanged", label)
}

// kitResolveJSInput returns the bytes to beautify, a label (URL/path/"stdin"),
// and a media type. An http(s):// argument is fetched; everything else (stdin
// "-" or a file path) goes through the shared kitReadInput.
func kitResolveJSInput(arg string) (data []byte, label, mediaType string, err error) {
	if strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://") {
		return kitFetchURL(arg)
	}
	b, label, err := kitReadInput(arg)
	return b, label, "application/javascript", err
}

// kitFetchURL GETs a URL through vigolium's proxy setting and returns the body.
func kitFetchURL(rawURL string) (data []byte, label, mediaType string, err error) {
	client := harvester.NewHTTPClient(kitBeautifyTimeout, globalProxy)
	req, rerr := http.NewRequest(http.MethodGet, rawURL, nil)
	if rerr != nil {
		return nil, rawURL, "", rerr
	}
	req.Header.Set("User-Agent", "vigolium-kit/js-beautify")
	resp, rerr := client.Do(req)
	if rerr != nil {
		return nil, rawURL, "", fmt.Errorf("fetching %s: %w", rawURL, rerr)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, rawURL, "", fmt.Errorf("fetching %s: HTTP %d", rawURL, resp.StatusCode)
	}
	body, rerr := io.ReadAll(resp.Body)
	if rerr != nil {
		return nil, rawURL, "", fmt.Errorf("reading %s: %w", rawURL, rerr)
	}
	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		ct = "application/javascript"
	}
	return body, rawURL, ct, nil
}
