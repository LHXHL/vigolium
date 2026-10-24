package cli

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/database"
)

// seedRefRecords writes records with chosen UUIDs into e's database: two that
// share the prefix aaaa1111, one unique (bbbb2222), and one in another project
// (cccc3333).
func seedRefRecords(t *testing.T, e *b5Env) {
	t.Helper()
	seedDryRunDB(t, e.db)
	repo := a3Repo(t, e.db)
	rec := func(uuid, path, project string) *database.HTTPRecord {
		return &database.HTTPRecord{
			UUID: uuid, ProjectUUID: project, Method: "GET", Scheme: "https",
			Hostname: "ref.example", Port: 443, Path: path, URL: "https://ref.example" + path,
			RawRequest:  []byte("GET " + path + " HTTP/1.1\r\nHost: ref.example\r\n\r\n"),
			RawResponse: []byte("HTTP/1.1 200 OK\r\nX-Probe: " + path + "\r\nContent-Type: text/plain\r\n\r\nbody of " + path),
			HasResponse: true, StatusCode: 200,
		}
	}
	_, err := repo.SaveRecordsBatch(context.Background(), []*database.HTTPRecord{
		rec("aaaa1111-0000-0000-0000-000000000001", "/one", database.DefaultProjectUUID),
		rec("aaaa1111-0000-0000-0000-000000000002", "/two", database.DefaultProjectUUID),
		rec("bbbb2222-0000-0000-0000-000000000003", "/three", database.DefaultProjectUUID),
		rec("cccc3333-0000-0000-0000-000000000004", "/other", "another-project"),
	})
	require.NoError(t, err)
}

func TestTrafficBodyTakesPositionalAndPrefix(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the CLI")
	}
	e := newB5Env(t)
	seedRefRecords(t, e)

	code, stdout, stderr := e.run(t, nil, "traffic", "body", "bbbb2222")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	assert.Equal(t, "body of /three", stdout)

	code, stdout, stderr = e.run(t, nil, "traffic", "headers", "bbbb2222-0000-0000-0000-000000000003", "-j")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	assert.Contains(t, stdout, "X-Probe")

	code, stdout, stderr = e.run(t, nil, "traffic", "body", "--uuid", "bbbb2222")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)

	code, stdout, stderr = e.run(t, nil, "traffic", "body", "bbbb2222", "--uuid", "aaaa1111", "-j")
	require.Equal(t, 2, code, "two different records named: stdout:\n%s\nstderr:\n%s", stdout, stderr)
}

func TestRecordPrefixAmbiguityAndProjectScope(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the CLI")
	}
	e := newB5Env(t)
	seedRefRecords(t, e)

	code, stdout, stderr := e.run(t, nil, "traffic", "body", "aaaa1111", "-j")
	require.Equal(t, 1, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	assert.Equal(t, string(apicontract.CodeAmbiguousID), errorCode(t, stdout))
	assert.Contains(t, stdout, "aaaa1111-0000-0000-0000-000000000001")
	assert.Contains(t, stdout, "aaaa1111-0000-0000-0000-000000000002")

	// Another project's record is not found, and is never named as a candidate.
	code, stdout, stderr = e.run(t, nil, "traffic", "body", "cccc3333", "-j")
	require.Equal(t, 1, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	assert.Equal(t, string(apicontract.CodeRecordNotFound), errorCode(t, stdout))

	// Too short to resolve.
	code, stdout, stderr = e.run(t, nil, "traffic", "body", "bbbb", "-j")
	require.Equal(t, 2, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)

	// The listing filter resolves a prefix to exact identity.
	code, stdout, stderr = e.run(t, nil, "traffic", "-j", "--compact", "--uuid", "bbbb2222", "--fields", "uuid")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	doc := oneDoc(t, stdout, stderr)
	items := doc["items"].([]any)
	require.Len(t, items, 1)
	assert.Equal(t, "bbbb2222-0000-0000-0000-000000000003", items[0].(map[string]any)["uuid"])

	code, stdout, stderr = e.run(t, nil, "traffic", "-j", "--uuid", "aaaa1111")
	require.Equal(t, 1, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	assert.Equal(t, string(apicontract.CodeAmbiguousID), errorCode(t, stdout))
}
