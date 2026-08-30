package server

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
)

// TestServerHeaderSingleVPrefix locks in the fix for a doubled "v" in the
// Server response header. pkg/cli.Version (and the goreleaser stamp) already
// carry the "v", so the header must not add another one.
func TestServerHeaderSingleVPrefix(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "version already prefixed",
			version: "v0.1.18-beta",
			want:    "Vigolium v0.1.18-beta (source https://github.com/vigolium/vigolium)",
		},
		{
			name:    "version stamped without prefix",
			version: "0.4.1",
			want:    "Vigolium v0.4.1 (source https://github.com/vigolium/vigolium)",
		},
		{
			name:    "unstamped build",
			version: "",
			want:    "Vigolium dev (source https://github.com/vigolium/vigolium)",
		},
		{
			name:    "whitespace only",
			version: "   ",
			want:    "Vigolium dev (source https://github.com/vigolium/vigolium)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := serverHeader(tt.version); got != tt.want {
				t.Errorf("serverHeader(%q) = %q, want %q", tt.version, got, tt.want)
			}
		})
	}
}

// TestServerHeaderOmitsLicense guards the banner against re-growing the license
// string that used to sit in front of the source URL.
func TestServerHeaderOmitsLicense(t *testing.T) {
	if got := serverHeader("v0.4.1"); strings.Contains(got, "AGPL") {
		t.Errorf("serverHeader() should not carry a license string, got %q", got)
	}
}

// TestAuthorHeaderMiddleware checks the X-Author companion header is stamped on
// the response.
func TestAuthorHeaderMiddleware(t *testing.T) {
	app := fiber.New()
	app.Use(AuthorHeaderMiddleware("@j3ssie"))
	app.Get("/", func(c fiber.Ctx) error { return c.SendString("ok") })

	resp, err := app.Test(httptest.NewRequest("GET", "/", nil))
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if got := resp.Header.Get("X-Author"); got != "@j3ssie" {
		t.Errorf("X-Author = %q, want %q", got, "@j3ssie")
	}
}

// TestAuthorHeaderSkippedWhenUnset locks in that an unset ServerConfig.Author
// leaves the header off entirely rather than emitting an empty one.
func TestAuthorHeaderSkippedWhenUnset(t *testing.T) {
	app := fiber.New()
	registerRoutes(app, &Handlers{config: ServerConfig{}}, ServerConfig{})

	resp, err := app.Test(httptest.NewRequest("GET", "/api/health", nil))
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if _, ok := resp.Header["X-Author"]; ok {
		t.Errorf("X-Author should be absent when the author is unset, got %q", resp.Header.Get("X-Author"))
	}
}
