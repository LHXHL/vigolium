package php2shell_version

import (
	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	php2shellinfra "github.com/vigolium/vigolium/pkg/modules/infra/php2shell"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

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
		ds: dedup.LazyDiskSet("php2shell_version"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest reports one result per host and advertised PHP version.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if !ctx.HasResponse() {
		return nil, nil
	}
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	var header, value string
	for _, name := range []string{"X-Powered-By", "Server"} {
		if v := ctx.Response().Header(name); php2shellinfra.VerdictFor(v) == php2shellinfra.Vulnerable {
			header, value = name, v
			break
		}
	}
	if header == "" {
		return nil, nil
	}
	version := php2shellinfra.Version(value)
	host := urlx.Host
	if ds := m.ds.Get(scanCtx.DedupMgr()); ds != nil && ds.IsSeen(host+"|"+version) {
		return nil, nil
	}
	fixed := php2shellinfra.FixedRelease(value)

	return []*output.ResultEvent{
		{
			ModuleID: ModuleID,
			Host:     host,
			URL:      urlx.String(),
			Matched:  urlx.String(),
			ExtractedResults: []string{
				header + ": " + value,
				"First fixed release on this branch: " + fixed,
			},
			Info: output.Info{
				Name:        "PHP " + version + " predates the php2shell fix (" + php2shellinfra.CVEs + ")",
				Description: "The " + header + " header advertises PHP " + version + "; the branch's first php2shell fix is " + fixed + ".",
				Severity:    ModuleSeverity,
				Confidence:  ModuleConfidence,
				Tags:        []string{"php", "php2shell", "cve-2026-109618", "cve-2026-109619", "outdated-component"},
				Reference:   php2shellinfra.References,
			},
			Metadata: map[string]any{
				"version":       version,
				"fixed_release": fixed,
			},
		},
	}, nil
}
