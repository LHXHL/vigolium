package server_action_input_audit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
)

func TestNew(t *testing.T) {
	t.Parallel()
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
}

// TestScanPerRequest_MissingValidation drives a Server Action that reads FormData and
// performs a DB write without any runtime validation library, which should flag.
func TestScanPerRequest_MissingValidation(t *testing.T) {
	t.Parallel()
	m := New()
	body := `'use server'
async function createUser(formData) {
  const name = formData.get('name');
  await prisma.user.create({ data: { name } });
}`
	ctx := modtest.HTTPCtx("/app/actions.js", "application/javascript", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)

	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Equal(t, "Server Action Input-Validation Candidate", results[0].Info.Name)
	assert.Equal(t, output.RecordKindCandidate, results[0].RecordKind)
	assert.False(t, results[0].IsFinding())
}

// TestScanPerRequest_WithValidation verifies that a Server Action using a zod schema
// (runtime validation) does not flag.
func TestScanPerRequest_WithValidation(t *testing.T) {
	t.Parallel()
	m := New()
	body := `'use server'
async function createUser(formData) {
  const data = z.object({ name: z.string() }).parse({ name: formData.get('name') });
  await prisma.user.create({ data });
}`
	ctx := modtest.HTTPCtx("/app/actions.js", "application/javascript", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_NoServerAction verifies that JS without a "use server" directive
// produces no findings.
func TestScanPerRequest_NoServerAction(t *testing.T) {
	t.Parallel()
	m := New()
	body := `function greet(name) { return "hello " + name; }`
	ctx := modtest.HTTPCtx("/app/util.js", "application/javascript", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
