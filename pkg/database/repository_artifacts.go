package database

import (
	"context"
	"fmt"
	"time"

	"github.com/vigolium/vigolium/pkg/deparos/jstangle/sourcemap"
)

const maxAnalysisArtifactBytes = 32 * 1024 * 1024

// SaveAnalysisArtifactForRecord stores a content-addressed immutable artifact
// beside an existing HTTP record. Duplicate writes of the same record/kind/hash
// are idempotent.
func (r *Repository) SaveAnalysisArtifactForRecord(ctx context.Context, artifact *AnalysisArtifact) error {
	if artifact == nil || artifact.HTTPRecordUUID == "" || artifact.Kind == "" || artifact.SHA256 == "" {
		return fmt.Errorf("invalid analysis artifact")
	}
	if len(artifact.Content) == 0 {
		return fmt.Errorf("analysis artifact content is empty")
	}
	if len(artifact.Content) > maxAnalysisArtifactBytes {
		return fmt.Errorf("analysis artifact exceeds %d-byte limit", maxAnalysisArtifactBytes)
	}

	var owner struct {
		ProjectUUID string `bun:"project_uuid"`
		ScanUUID    string `bun:"scan_uuid"`
	}
	if err := r.db.NewSelect().Table("http_records").
		Column("project_uuid", "scan_uuid").
		Where("uuid = ?", artifact.HTTPRecordUUID).
		Scan(ctx, &owner); err != nil {
		return fmt.Errorf("resolve artifact record: %w", err)
	}

	artifact.ProjectUUID = defaultProjectUUID(owner.ProjectUUID)
	artifact.ScanUUID = owner.ScanUUID
	artifact.ByteLength = int64(len(artifact.Content))
	if artifact.CreatedAt.IsZero() {
		artifact.CreatedAt = time.Now()
	}
	_, err := r.db.NewInsert().Model(artifact).On("CONFLICT DO NOTHING").Exec(ctx)
	return err
}

// AnalysisArtifactKindSourceMapOriginal labels an original source file recovered
// from a source map's sourcesContent. Aliased from the sourcemap package, which
// owns the name for the writers on the other side of this package boundary.
const AnalysisArtifactKindSourceMapOriginal = sourcemap.ArtifactKindOriginal

// StreamAnalysisArtifactsByKind walks stored artifacts of one kind in id order,
// handing each to fn. It streams rather than returning a slice because recovered
// source content is unbounded in aggregate — one SPA source map can carry
// hundreds of files — and the callers scan each body once and discard it.
//
// A zero-length page ends the walk; fn returning an error aborts it.
func (r *Repository) StreamAnalysisArtifactsByKind(
	ctx context.Context,
	projectUUID, kind string,
	batchSize int,
	fn func(artifact *AnalysisArtifact) error,
) error {
	if kind == "" {
		return fmt.Errorf("artifact kind is required")
	}
	if batchSize <= 0 {
		batchSize = 100
	}
	cursor := int64(0)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		var page []AnalysisArtifact
		query := r.db.NewSelect().Model(&page).
			Where("kind = ?", kind).
			Where("id > ?", cursor).
			Order("id ASC").
			Limit(batchSize)
		if projectUUID != "" {
			query = query.Where("project_uuid = ?", projectUUID)
		}
		if err := query.Scan(ctx); err != nil {
			return fmt.Errorf("stream analysis artifacts: %w", err)
		}
		if len(page) == 0 {
			return nil
		}
		for i := range page {
			cursor = page[i].ID
			if err := fn(&page[i]); err != nil {
				return err
			}
		}
	}
}

// SaveAnalysisArtifact is the primitive-argument adapter used by input sources
// that deliberately avoid importing the database package in their interfaces.
func (r *Repository) SaveAnalysisArtifact(
	ctx context.Context,
	httpRecordUUID, kind, filename, mediaType, sha256 string,
	content []byte,
	metadata string,
) error {
	return r.SaveAnalysisArtifactForRecord(ctx, &AnalysisArtifact{
		HTTPRecordUUID: httpRecordUUID,
		Kind:           kind,
		Filename:       filename,
		MediaType:      mediaType,
		SHA256:         sha256,
		Content:        content,
		Metadata:       metadata,
	})
}
