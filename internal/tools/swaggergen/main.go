// Command swaggergen regenerates components.schemas of the REST API's OpenAPI
// document from the Go request/response types registered in
// server.SwaggerSchemaTypes, keeping the hand-written paths and prose, and
// writes the canonical copy plus the copy embedded into the server binary.
//
//	go run ./internal/tools/swaggergen            # what `make swagger` runs
//	go run ./internal/tools/swaggergen -out DIR   # write both copies under DIR (verify-generated)
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

const (
	canonicalPath = "docs/development/api-swagger.json"
	embeddedPath  = "pkg/server/swagger_spec.json"
)

func main() {
	in := flag.String("in", canonicalPath, "spec to read paths and hand-written prose from")
	outDir := flag.String("out", "", "write both copies under this directory instead of in place")
	flag.Parse()

	if err := run(*in, *outDir); err != nil {
		fmt.Fprintln(os.Stderr, "swaggergen:", err)
		os.Exit(1)
	}
}

func run(in, outDir string) error {
	spec, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	out, err := generate(spec)
	if err != nil {
		return err
	}
	for _, p := range []string{canonicalPath, embeddedPath} {
		dst := filepath.Join(outDir, p)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(dst, out, 0o644); err != nil {
			return err
		}
	}
	return nil
}
