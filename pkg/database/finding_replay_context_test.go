package database

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/output"
)

func TestFinding_FromResultEvent_ReplayContext(t *testing.T) {
	var f Finding
	require.NoError(t, f.FromResultEvent(&output.ResultEvent{
		ModuleID:           "m",
		OriginRecordUUID:   "rec-1",
		InsertionPointType: "URL_PARAM",
		FuzzingParameter:   "id",
		Payload:            "1'",
	}))
	assert.Equal(t, "rec-1", f.OriginRecordUUID)
	assert.Equal(t, &FindingInsertionPoint{Type: "URL_PARAM", Name: "id"}, f.InsertionPoint)
	assert.Equal(t, "1'", f.Payload)

	var bare Finding
	require.NoError(t, bare.FromResultEvent(&output.ResultEvent{ModuleID: "m"}))
	assert.Nil(t, bare.InsertionPoint, "no point is recorded for a result that names none")
	assert.Empty(t, bare.OriginRecordUUID)
}
