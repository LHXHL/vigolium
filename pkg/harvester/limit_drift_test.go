package harvester_test

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/harvester"
)

// The limit code is restated in pkg/harvester to keep the database layer out of
// its imports (database → internal/config → harvester would cycle); this pins
// it to the shared vocabulary. It lives in the external test package for the
// same reason.
func TestLimitCDXMaxRowsMatchesDatabase(t *testing.T) {
	if harvester.LimitCDXMaxRows != database.LimitCDXMaxRows {
		t.Fatalf("LimitCDXMaxRows = %q, database says %q", harvester.LimitCDXMaxRows, database.LimitCDXMaxRows)
	}
}
