package verbose_error_stacktrace

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

// Module implements the Verbose Error Stack Trace passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Verbose Error Stack Trace module.
func New() *Module {
	m := &Module{
		BasePassiveModule: modkit.NewBasePassiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.PassiveScanScopeResponse,
		),
		ds: dedup.LazyDiskSet("passive_verbose_error_stacktrace"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest analyzes response body for verbose stack traces.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if utils.IsMediaAndJSURL(urlx.Path) {
		return nil, nil
	}

	if ctx.Response() == nil {
		return nil, nil
	}
	if modkit.IsEdgeBlockedResponse(ctx.Response()) {
		return nil, nil
	}

	// Skip binary content
	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	if strings.Contains(ct, "image/") || strings.Contains(ct, "audio/") ||
		strings.Contains(ct, "video/") || strings.Contains(ct, "octet-stream") {
		return nil, nil
	}

	// Dedup by host+path
	var diskSet *dedup.DiskSet
	if scanCtx != nil {
		diskSet = m.ds.Get(scanCtx.DedupMgr())
	}
	dedupKey := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
	if diskSet != nil && diskSet.IsSeen(dedupKey) {
		return nil, nil
	}

	body := ctx.Response().BodyToString()
	if body == "" {
		return nil, nil
	}

	var results []*output.ResultEvent

	for _, stp := range modkit.StackTracePatterns {
		match := stp.Regexp.FindString(body)
		if match == "" {
			continue
		}

		kind := output.RecordKindObservation
		grade := output.EvidenceGradeObservation
		sev := severity.Info
		description := fmt.Sprintf("A structured %s stack-trace pattern appears in a successful response. It is retained as reconnaissance context because documentation and examples can contain the same structure.", stp.Technology)
		if status := ctx.Response().StatusCode(); status >= 400 && status <= 599 {
			kind = output.RecordKindCandidate
			grade = output.EvidenceGradeCandidate
			sev = stp.Severity
			description = fmt.Sprintf("A structured %s stack trace with file paths appears in an HTTP error response. The disclosure is strongly supported, but no underlying injection or code-execution flaw is inferred.", stp.Technology)
		}

		results = append(results, &output.ResultEvent{
			ModuleID:      ModuleID,
			RecordKind:    kind,
			EvidenceGrade: grade,
			Host:          urlx.Host,
			URL:           urlx.String(),
			Matched:       urlx.String(),
			Request:       string(ctx.Request().Raw()),
			Response:      string(ctx.Response().Raw()),
			ExtractedResults: []string{
				fmt.Sprintf("Technology: %s", stp.Technology),
				fmt.Sprintf("HTTP status: %d", ctx.Response().StatusCode()),
				fmt.Sprintf("Stack trace: %s", truncate(match, 200)),
			},
			Info: output.Info{
				Name:        fmt.Sprintf("%s Stack Trace Exposed", stp.Technology),
				Description: description,
				Severity:    sev,
				Confidence:  stp.Confidence,
				Tags:        []string{"passive", "stacktrace", strings.ToLower(stp.Technology)},
			},
			Metadata: map[string]any{
				"status_code":            ctx.Response().StatusCode(),
				"error_context":          ctx.Response().StatusCode() >= 400 && ctx.Response().StatusCode() <= 599,
				"underlying_vuln_tested": false,
			},
		})
	}

	return results, nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
