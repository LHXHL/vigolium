package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/database"
)

// TestProjectUUIDMiddleware_Contract covers D8: an unknown X-Project-UUID is a
// 404 unless creation is requested, a malformed one is a 400, and the
// default project, public paths and project management are untouched.
func TestProjectUUIDMiddleware_Contract(t *testing.T) {
	const unknown = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

	newApp := func(t *testing.T, cfg ProjectMiddlewareConfig) (*fiber.App, *database.Repository) {
		_, repo := newProjectModelTestDB(t)
		app := fiber.New(fiber.Config{ErrorHandler: apiErrorHandler})
		app.Use(apiVersionMiddleware(1))
		app.Use(ProjectUUIDMiddleware(repo, cfg))
		ok := func(c fiber.Ctx) error { return c.SendString(getProjectUUID(c)) }
		app.Get("/api/findings", ok)
		app.Post("/api/scan-url", ok)
		app.Get("/api/projects", ok)
		app.Get("/api/projects/:uuid", ok)
		app.Get("/health", ok)
		return app, repo
	}
	exists := func(repo *database.Repository, id string) bool {
		_, err := repo.GetProjectByUUID(context.Background(), id)
		return err == nil
	}
	hdr := func(kv ...string) map[string]string {
		m := map[string]string{}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return m
	}

	t.Run("unknown → 404 project_not_found, no row", func(t *testing.T) {
		app, repo := newApp(t, ProjectMiddlewareConfig{})
		resp, body := doReq2(t, app, http.MethodGet, "/api/findings", "", hdr("X-Project-UUID", unknown))
		assert.Equal(t, 404, resp.StatusCode)
		var e ErrorResponse
		require.NoError(t, json.Unmarshal(body, &e))
		assert.Equal(t, string(apicontract.CodeProjectNotFound), e.ErrorCode)
		assert.Contains(t, e.Details, "X-Project-Create")
		assert.False(t, exists(repo, unknown))
	})
	t.Run("unknown → v2 error object", func(t *testing.T) {
		app, _ := newApp(t, ProjectMiddlewareConfig{})
		resp, body := doReq2(t, app, http.MethodGet, "/api/findings", "", hdr("X-Project-UUID", unknown, apicontract.RESTAPIVersionHeader, "2"))
		assert.Equal(t, 404, resp.StatusCode)
		var e apicontract.RESTErrorEnvelope
		require.NoError(t, json.Unmarshal(body, &e))
		assert.Equal(t, apicontract.CodeProjectNotFound, e.Error.Code)
		assert.Equal(t, 404, e.Error.Status)
	})
	t.Run("X-Project-Create: 1 → created", func(t *testing.T) {
		app, repo := newApp(t, ProjectMiddlewareConfig{})
		resp, body := doReq2(t, app, http.MethodPost, "/api/scan-url", `{}`, hdr("X-Project-UUID", unknown, "X-Project-Create", "1"))
		assert.Equal(t, 200, resp.StatusCode, string(body))
		assert.Equal(t, unknown, string(body))
		assert.True(t, exists(repo, unknown))
	})
	t.Run("?create=1 → created", func(t *testing.T) {
		app, repo := newApp(t, ProjectMiddlewareConfig{})
		resp, _ := doReq2(t, app, http.MethodGet, "/api/findings?create=1", "", hdr("X-Project-UUID", unknown))
		assert.Equal(t, 200, resp.StatusCode)
		assert.True(t, exists(repo, unknown))
	})
	t.Run("server.auto_create_projects → created", func(t *testing.T) {
		app, repo := newApp(t, ProjectMiddlewareConfig{AutoCreate: true})
		resp, _ := doReq2(t, app, http.MethodGet, "/api/findings", "", hdr("X-Project-UUID", unknown))
		assert.Equal(t, 200, resp.StatusCode)
		assert.True(t, exists(repo, unknown))
	})
	t.Run("existing project passes", func(t *testing.T) {
		app, repo := newApp(t, ProjectMiddlewareConfig{})
		require.NoError(t, repo.CreateProject(context.Background(), &database.Project{UUID: unknown, Name: "x", OwnerUUID: database.DefaultUserUUID}))
		resp, body := doReq2(t, app, http.MethodGet, "/api/findings", "", hdr("X-Project-UUID", unknown))
		assert.Equal(t, 200, resp.StatusCode)
		assert.Equal(t, unknown, string(body))
	})
	t.Run("malformed → 400 invalid_project_uuid", func(t *testing.T) {
		app, _ := newApp(t, ProjectMiddlewareConfig{AutoCreate: true})
		for _, bad := range []string{"proj-a", "{" + unknown + "}", "urn:uuid:" + unknown, unknown + "0"} {
			resp, body := doReq2(t, app, http.MethodGet, "/api/findings", "", hdr("X-Project-UUID", bad))
			assert.Equal(t, 400, resp.StatusCode, bad)
			assert.Contains(t, string(body), `"error_code":"invalid_project_uuid"`, bad)
		}
	})
	t.Run("default project untouched", func(t *testing.T) {
		app, _ := newApp(t, ProjectMiddlewareConfig{})
		for _, h := range []map[string]string{nil, hdr("X-Project-UUID", database.DefaultProjectUUID)} {
			resp, body := doReq2(t, app, http.MethodGet, "/api/findings", "", h)
			assert.Equal(t, 200, resp.StatusCode)
			assert.Equal(t, database.DefaultProjectUUID, string(body))
		}
	})
	t.Run("public and project-management paths ignore the header", func(t *testing.T) {
		app, repo := newApp(t, ProjectMiddlewareConfig{})
		for _, p := range []string{"/health", "/api/projects", "/api/projects/" + unknown} {
			resp, _ := doReq2(t, app, http.MethodGet, p, "", hdr("X-Project-UUID", "stale-not-a-uuid"))
			assert.Equal(t, 200, resp.StatusCode, p)
			resp, _ = doReq2(t, app, http.MethodGet, p, "", hdr("X-Project-UUID", unknown))
			assert.Equal(t, 200, resp.StatusCode, p)
		}
		assert.False(t, exists(repo, unknown))
	})
	t.Run("DB error → 503 database_unavailable", func(t *testing.T) {
		db, repo := newProjectModelTestDB(t)
		app := fiber.New()
		app.Use(ProjectUUIDMiddleware(repo))
		app.Get("/api/findings", func(c fiber.Ctx) error { return c.SendString("ran") })
		require.NoError(t, db.Close())
		resp, body := doReq2(t, app, http.MethodGet, "/api/findings", "", hdr("X-Project-UUID", unknown))
		assert.Equal(t, 503, resp.StatusCode, string(body))
		assert.Contains(t, string(body), `"error_code":"database_unavailable"`)
	})
}
