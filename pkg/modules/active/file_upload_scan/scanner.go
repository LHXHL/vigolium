package file_upload_scan

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/oast/oastclass"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

type Module struct {
	modkit.BaseActiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
}

func New() *Module {
	m := &Module{
		BaseActiveModule: modkit.NewBaseActiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.AllInsertionPointTypes,
		),
		rhm: dedup.LazyDefaultRHM("file_upload_scan"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// IncludesBaseCanProcess returns false because this module uses custom CanProcess.
func (m *Module) IncludesBaseCanProcess() bool { return false }

// CanProcess returns true only for multipart/form-data requests with a filename.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Request() == nil {
		return false
	}

	ct := strings.ToLower(ctx.Request().Header("Content-Type"))
	if !strings.Contains(ct, "multipart/form-data") {
		return false
	}

	// Check for filename in body
	body := ctx.Request().BodyToString()
	return strings.Contains(body, "filename=")
}

// ScanPerRequest tests file upload with various bypass probes.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	var results []*output.ResultEvent

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	marker := generateMarker()

	// If a collaborator is configured, mint one out-of-band host for this scan and
	// embed it in the PHP shell / SVG probes. A callback proves the uploaded file
	// executed or was rendered even when it is stored out of our reach — an
	// execution proof independent of the retrieval path below. Findings for these
	// arrive asynchronously via the OAST polling callback.
	var oastHost string
	if oast := scanCtx.OASTProv(); oast != nil && oast.Enabled() {
		oastHost = modkit.OASTURLFor(oast, oastclass.CMDI, urlx.String(), "file", "file-upload code execution (command)", ModuleID, ctx.Request().ID())
		if oastHost != "" {
			oast.RecordPayload(oastHost, "Uploaded PHP web shell / SVG image issuing an out-of-band request on execution or render")
		}
	}

	probes := buildProbes(marker, oastHost)

	for i, probe := range probes {
		modified, err := replaceFilePart(ctx.Request().Raw(), probe)
		if err != nil {
			continue
		}

		// modified is well-formed raw, so wrap directly instead of re-parsing on this hot path.
		fuzzedReq := httpmsg.NewRequestResponseRaw(modified, ctx.Service())

		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}

		respStatus := 0
		respBody := ""
		if resp.Response() != nil {
			respStatus = resp.Response().StatusCode
			respBody = resp.FullResponseString()
		}
		resp.Close()

		// Early abort on first probe: strict server validation
		if i == 0 && (respStatus == 400 || respStatus == 403 || respStatus == 415) {
			return results, nil
		}

		// Skip non-success responses
		if respStatus < 200 || respStatus >= 300 {
			continue
		}

		// Strict drop-on-fail: a 2xx on the upload endpoint alone is not proof of
		// an arbitrary file upload — many endpoints return 200/redirect even when
		// the upload is rejected, stored out of reach, or handled by middleware.
		// Only report when the file is independently retrievable AND echoes our
		// unique marker (upload accepted + file fetchable + marker present), which
		// is the actual vulnerability. Unverified candidates are dropped.
		verified, executed, verifyBody := m.verifyUpload(ctx, httpClient, respBody, probe, marker)
		if !verified {
			continue
		}

		// Two confirmation outcomes with distinct impact:
		//   - executed: the retrieved file printed the arithmetic signature, so the
		//     server ran our code — remote code execution (Critical).
		//   - stored:   the file is retrievable and echoes the marker verbatim, so an
		//     arbitrary file is uploaded and served, but we did not observe execution
		//     (High). Either way the marker/signature match is unforgeable.
		name := "Arbitrary File Upload"
		sev := severity.High
		desc := fmt.Sprintf("File upload and retrieval confirmed: %s (%s)", probe.name, probe.filename)
		signal := "Verified: stored + retrievable"
		if executed {
			name = "Arbitrary File Upload to Remote Code Execution"
			sev = severity.Critical
			desc = fmt.Sprintf("Uploaded file executed server-side: %s (%s) — the retrieved file returned the computed arithmetic signature, proving code execution.", probe.name, probe.filename)
			signal = "Verified: executed (arithmetic signature)"
		}

		results = append(results, &output.ResultEvent{
			URL:              urlx.String(),
			Request:          string(modified),
			Response:         verifyBody,
			FuzzingParameter: "file",
			ExtractedResults: []string{
				fmt.Sprintf("Probe: %s", probe.name),
				fmt.Sprintf("Filename: %s", probe.filename),
				signal,
			},
			Info: output.Info{
				Name:        name,
				Description: desc,
				Severity:    sev,
				Confidence:  severity.Certain,
			},
		})

		return results, nil // One confirmed finding is enough
	}

	return results, nil
}

// verifyUpload attempts to access the uploaded file to confirm it. It returns
// verified (the file was retrieved and carries our marker), executed (the retrieved
// file contained the arithmetic execution signature, i.e. the server ran the code
// rather than serving it as text), and the retrieved body. The execution check is
// tried first so a genuinely-executing endpoint is rated as RCE rather than a plain
// upload.
func (m *Module) verifyUpload(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	uploadResponse string,
	probe uploadProbe,
	marker string,
) (verified, executed bool, body string) {
	// Try to extract upload path from response
	uploadPath := extractUploadPath(uploadResponse)

	var pathsToTry []string
	if uploadPath != "" {
		pathsToTry = append(pathsToTry, uploadPath)
	}

	// Also try common upload directories
	for _, dir := range commonUploadDirs {
		pathsToTry = append(pathsToTry, dir+probe.filename)
	}

	execSig := markerExecSignature(marker)
	for _, path := range pathsToTry {
		fetched, err := m.fetchPath(ctx, httpClient, path)
		if err != nil {
			continue
		}

		if strings.Contains(fetched, execSig) {
			return true, true, fetched // interpreter ran the code -> RCE
		}
		if strings.Contains(fetched, marker) {
			return true, false, fetched // stored + retrievable, execution not observed
		}
	}

	return false, false, ""
}

// fetchPath sends a GET request to the specified path.
func (m *Module) fetchPath(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	path string,
) (string, error) {
	raw := ctx.Request().Raw()

	modified, err := httpmsg.SetPath(raw, path)
	if err != nil {
		return "", err
	}
	modified, err = httpmsg.SetMethod(modified, "GET")
	if err != nil {
		return "", err
	}
	// Remove Content-Type and body for GET request
	modified, err = httpmsg.ClearBody(modified)
	if err != nil {
		return "", err
	}

	// modified is well-formed raw, so wrap directly instead of re-parsing on this hot path.
	getReq := httpmsg.NewRequestResponseRaw(modified, ctx.Service())

	resp, _, err := httpClient.Execute(getReq, http.Options{})
	if err != nil {
		return "", err
	}
	defer resp.Close()

	if resp.Response() == nil || resp.Response().StatusCode != 200 {
		return "", fmt.Errorf("non-200 response: %d", resp.Response().StatusCode)
	}

	return resp.FullResponseString(), nil
}
