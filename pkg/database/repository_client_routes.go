package database

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
)

// JSFactsArtifactKind is the analysis artifact discovery stores per JS asset
// with the asset's non-request jstangle facts (routes, GraphQL operations,
// WebSocket/SSE endpoints, asset references, path literals, request hints).
const JSFactsArtifactKind = "jstangle-facts"

// clientRouteArtifactCap bounds how many jstangle-facts artifacts one
// ListClientRoutes call reads; each carries at most a few thousand routes.
const clientRouteArtifactCap = 2000

// ClientRoute is one client-side route a JS asset declared, read back from a
// jstangle-facts artifact, together with the origin of the record the artifact
// is anchored to (the asset's own record or, for an unrecorded asset, a record
// of its origin). Path is the route as the router declares it; FullPath is the
// helper's normalized absolute route (parents joined) when it reported one.
type ClientRoute struct {
	Scheme   string
	Hostname string
	Port     int

	Path           string
	FullPath       string
	FullPathStatic bool
	RouteType      string
	Extractor      string
	Confidence     string
	SourceURL      string
	ScanUUID       string
}

// clientRouteRow is one artifact row joined to its anchor record's origin.
type clientRouteRow struct {
	Content  []byte `bun:"content"`
	ScanUUID string `bun:"scan_uuid"`
	Scheme   string `bun:"scheme"`
	Hostname string `bun:"hostname"`
	Port     int    `bun:"port"`
}

// jsFactBundleRoutes is the slice of a jstangle-facts artifact that carries
// client routes. Declared here rather than imported, as jsFactBundleNames is,
// so the database layer does not depend on the discovery engine.
type jsFactBundleRoutes struct {
	SourceURL    string `json:"source_url"`
	ClientRoutes []struct {
		Path struct {
			Rendered string `json:"rendered"`
		} `json:"path"`
		FullPath *struct {
			Rendered string `json:"rendered"`
			Static   bool   `json:"static"`
		} `json:"fullPath"`
		RouteType  string `json:"routeType"`
		Provenance struct {
			Extractor  string `json:"extractor"`
			Confidence string `json:"confidence"`
		} `json:"provenance"`
	} `json:"clientRoute"`
}

// ListClientRoutes returns the client routes projectUUID's jstangle-facts
// artifacts declare, oldest artifact first, deduplicated per origin and route.
// scanUUID, when set, keeps only artifacts stamped with that scan (their
// anchor record's scan); hosts, when set, keeps only routes anchored on those
// origins. limit caps the routes returned (0 = no cap). Routes are returned
// as declared: filtering redirects and low-confidence guesses and making
// parameters concrete is the caller's job (see clientroute).
func (r *Repository) ListClientRoutes(ctx context.Context, scanUUID, projectUUID string, hosts []HostTarget, limit int) ([]ClientRoute, error) {
	var rows []clientRouteRow
	q := r.db.NewSelect().TableExpr("analysis_artifacts AS aa").
		ColumnExpr("aa.content, aa.scan_uuid, r.scheme, r.hostname, r.port").
		Join("JOIN http_records AS r ON r.uuid = aa.http_record_uuid").
		Where("aa.kind = ?", JSFactsArtifactKind)
	if projectUUID != "" {
		q = q.Where("aa.project_uuid = ?", projectUUID)
	}
	if scanUUID != "" {
		q = q.Where("aa.scan_uuid = ?", scanUUID)
	}
	// hostname/scheme/port exist only on http_records, so the shared
	// unqualified filter binds to the joined record.
	q = applyHostScopeFilter(q, hosts)
	if err := q.OrderExpr("aa.id ASC").Limit(clientRouteArtifactCap).Scan(ctx, &rows); err != nil {
		return nil, err
	}

	var out []ClientRoute
	seen := make(map[string]struct{})
	for _, row := range rows {
		var bundle jsFactBundleRoutes
		if err := json.Unmarshal(row.Content, &bundle); err != nil {
			continue
		}
		for _, cr := range bundle.ClientRoutes {
			route := ClientRoute{
				Scheme: row.Scheme, Hostname: row.Hostname, Port: row.Port,
				Path: cr.Path.Rendered, RouteType: cr.RouteType,
				Extractor: cr.Provenance.Extractor, Confidence: cr.Provenance.Confidence,
				SourceURL: bundle.SourceURL, ScanUUID: row.ScanUUID,
			}
			if cr.FullPath != nil {
				route.FullPath, route.FullPathStatic = cr.FullPath.Rendered, cr.FullPath.Static
			}
			if strings.TrimSpace(route.Path) == "" && strings.TrimSpace(route.FullPath) == "" {
				continue
			}
			key := strings.ToLower(row.Scheme+"://"+row.Hostname) + ":" + strconv.Itoa(row.Port) + "\x00" + route.Path + "\x00" + route.FullPath
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, route)
			if limit > 0 && len(out) >= limit {
				return out, nil
			}
		}
	}
	return out, nil
}
