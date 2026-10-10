package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/invopop/jsonschema"
	"github.com/spf13/cobra"

	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/contract"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// `vigolium schema` prints the machine contract as JSON Schema (draft
// 2020-12): the -j document of each registered command (schema_registry.go),
// every --events line type (pkg/scanevents/schema.go), the -j error envelope,
// and standalone documents such as the scan plan. Without -j the output is
// the bare schema, ready to hand to a validator; with -j it is the usual
// envelope whose items are {name, kind, schema}.

var schemaCmd = &cobra.Command{
	Use:   "schema",
	Short: "Print the JSON Schema of -j documents, --events lines and the error envelope",
	Long: "Print the machine contract as JSON Schema (draft 2020-12), generated from the same Go types the " +
		"commands emit.\n\n" +
		"  schema                   list what has a schema (also: schema list)\n" +
		"  schema command <name>    one command's -j document (e.g. `schema command finding`)\n" +
		"  schema event [type]      one --events line type, or every type as oneOf\n" +
		"  schema error             the -j error envelope, with the closed error.code vocabulary\n" +
		"  schema plan              the scan plan document (scan --dry-run, the scan.plan event)\n" +
		"  schema all               everything above in one object\n\n" +
		"Without -j the bare schema is printed; with -j the result is an envelope whose items are " +
		"{name, kind, schema}. The same files are committed under docs/schema (make schema).",
	Example: "  vigolium schema\n" +
		"  vigolium schema command finding > finding.schema.json\n" +
		"  vigolium schema command scan status\n" +
		"  vigolium schema event phase.progress\n" +
		"  vigolium schema error -j",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error { return runSchemaList(cmd) },
}

var schemaListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List the commands, event types and documents that have a schema",
	Args:    cobra.NoArgs,
	RunE:    func(cmd *cobra.Command, _ []string) error { return runSchemaList(cmd) },
}

var schemaCommandCmd = &cobra.Command{
	Use:   "command <name>",
	Short: "Print one command's -j document schema",
	Long: "Print the JSON Schema of one command's -j document. The name is the command path without " +
		"`vigolium`, as the document's `command` field carries it; a multi-word path may be quoted or not " +
		"(`schema command scan status`).",
	Args: cobra.MinimumNArgs(1),
	ValidArgsFunction: func(_ *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
		if len(args) > 0 {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		return contract.CommandNames(), cobra.ShellCompDirectiveNoFileComp
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		name := strings.Join(strings.Fields(strings.Join(args, " ")), " ")
		if _, ok := contract.LookupCommand(name); !ok {
			return usageErrorf("no schema for command %q; registered: %s",
				name, strings.Join(contract.CommandNames(), ", "))
		}
		s, err := contract.CommandSchema(name)
		if err != nil {
			return err
		}
		return emitSchema(cmd, schemaEntry{Name: name, Kind: schemaKindCommand}, s)
	},
}

var schemaEventCmd = &cobra.Command{
	Use:   "event [type]",
	Short: "Print the schema of one --events line type, or of any line",
	Args:  cobra.MaximumNArgs(1),
	ValidArgsFunction: func(_ *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
		if len(args) > 0 {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		return contract.EventTypes(), cobra.ShellCompDirectiveNoFileComp
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			s, err := contract.EventsSchema()
			if err != nil {
				return err
			}
			return emitSchema(cmd, schemaEntry{Name: "events", Kind: schemaKindEvent}, s)
		}
		typ := strings.TrimSpace(args[0])
		if _, ok := contract.LookupEvent(typ); !ok {
			return usageErrorf("unknown event type %q; known: %s", typ, strings.Join(contract.EventTypes(), ", "))
		}
		s, err := contract.EventSchema(typ)
		if err != nil {
			return err
		}
		return emitSchema(cmd, schemaEntry{Name: typ, Kind: schemaKindEvent}, s)
	},
}

var schemaErrorCmd = &cobra.Command{
	Use:   "error",
	Short: "Print the -j error envelope schema (error.code is a closed enum)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		return emitSchema(cmd, schemaEntry{Name: "error", Kind: schemaKindError}, contract.ErrorSchema())
	},
}

var schemaPlanCmd = &cobra.Command{
	Use:   "plan",
	Short: "Print the scan plan schema (scan --dry-run, the scan.plan event)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		if _, ok := contract.LookupDocument(schemaDocPlan); !ok {
			return codedErrorf(apicontract.CodeNotFound, "the scan plan schema is not registered in this build")
		}
		s, err := contract.DocumentSchema(schemaDocPlan)
		if err != nil {
			return err
		}
		return emitSchema(cmd, schemaEntry{Name: schemaDocPlan, Kind: schemaKindDocument}, s)
	},
}

var schemaAllCmd = &cobra.Command{
	Use:   "all",
	Short: "Print every schema in one object",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		entries, err := schemaEntries(true)
		if err != nil {
			return err
		}
		if globalJSON {
			return emitRead(cmd, "", entries, int64(len(entries)), 0, len(entries))
		}
		all, err := schemaBundle()
		if err != nil {
			return err
		}
		return writeSchemaJSON(all)
	},
}

func init() {
	rootCmd.AddCommand(schemaCmd)
	schemaCmd.AddCommand(schemaListCmd, schemaCommandCmd, schemaEventCmd, schemaErrorCmd, schemaPlanCmd, schemaAllCmd)
}

// Entry kinds.
const (
	schemaKindCommand  = "command"
	schemaKindEvent    = "event"
	schemaKindError    = "error"
	schemaKindDocument = "document"

	// schemaDocPlan is the scan plan's document name (registered by the plan
	// package's owner; absent from a build that has none).
	schemaDocPlan = "plan"
)

// schemaEntry is one row of `schema` / `schema list`, and with -j one item of
// every schema subcommand (Schema set).
type schemaEntry struct {
	Name string `json:"name"`
	// Kind is command, event, error or document.
	Kind string `json:"kind"`
	// EnvelopeKind is a command document's own `kind`: read, mutation or scan.
	EnvelopeKind string           `json:"envelope_kind,omitempty"`
	Description  string           `json:"description,omitempty"`
	Schema       *contract.Schema `json:"schema,omitempty"`
}

// schemaEntries lists everything that has a schema: commands (sorted), event
// types (vocabulary order), the error envelope, then documents.
func schemaEntries(withSchema bool) ([]schemaEntry, error) {
	var out []schemaEntry
	for _, name := range contract.CommandNames() {
		c, _ := contract.LookupCommand(name)
		e := schemaEntry{Name: name, Kind: schemaKindCommand, EnvelopeKind: c.Kind, Description: c.Description}
		if withSchema {
			s, err := contract.CommandSchema(name)
			if err != nil {
				return nil, err
			}
			e.Schema = s
		}
		out = append(out, e)
	}
	for _, typ := range contract.EventTypes() {
		f, _ := contract.LookupEvent(typ)
		e := schemaEntry{Name: typ, Kind: schemaKindEvent, Description: f.Description}
		if withSchema {
			s, err := contract.EventSchema(typ)
			if err != nil {
				return nil, err
			}
			e.Schema = s
		}
		out = append(out, e)
	}
	e := schemaEntry{Name: "error", Kind: schemaKindError, Description: "The -j error envelope (ok:false)."}
	if withSchema {
		e.Schema = contract.ErrorSchema()
	}
	out = append(out, e)
	for _, name := range contract.DocumentNames() {
		d, _ := contract.LookupDocument(name)
		e := schemaEntry{Name: name, Kind: schemaKindDocument, Description: d.Description}
		if withSchema {
			s, err := contract.DocumentSchema(name)
			if err != nil {
				return nil, err
			}
			e.Schema = s
		}
		out = append(out, e)
	}
	return out, nil
}

// schemaBundle is `schema all` without -j: one object keyed by section.
func schemaBundle() (map[string]any, error) {
	commands := map[string]*contract.Schema{}
	for _, name := range contract.CommandNames() {
		s, err := contract.CommandSchema(name)
		if err != nil {
			return nil, err
		}
		commands[name] = s
	}
	events, err := contract.EventsSchema()
	if err != nil {
		return nil, err
	}
	documents := map[string]*contract.Schema{}
	for _, name := range contract.DocumentNames() {
		s, err := contract.DocumentSchema(name)
		if err != nil {
			return nil, err
		}
		documents[name] = s
	}
	return map[string]any{
		"$schema":        jsonschema.Version,
		"schema_version": apicontract.SchemaVersion,
		"commands":       commands,
		"events":         events,
		"error":          contract.ErrorSchema(),
		"documents":      documents,
	}, nil
}

func runSchemaList(cmd *cobra.Command) error {
	entries, err := schemaEntries(false)
	if err != nil {
		return err
	}
	if globalJSON {
		return emitRead(cmd, "", entries, int64(len(entries)), 0, len(entries))
	}
	for _, e := range entries {
		kind := e.Kind
		if e.EnvelopeKind != "" {
			kind += " (" + e.EnvelopeKind + ")"
		}
		fmt.Printf("%-24s %-20s %s\n", terminal.Cyan(e.Name), kind, terminal.Gray(e.Description))
	}
	if _, ok := contract.LookupDocument(schemaDocPlan); !ok {
		fmt.Fprintf(os.Stderr, "%s the scan plan schema is not registered in this build\n", terminal.InfoSymbol())
	}
	return nil
}

// emitSchema prints one schema: bare without -j, as a one-item envelope with.
func emitSchema(cmd *cobra.Command, e schemaEntry, s *contract.Schema) error {
	if globalJSON {
		e.Schema = s
		if e.Kind == schemaKindCommand {
			if c, ok := contract.LookupCommand(e.Name); ok {
				e.EnvelopeKind, e.Description = c.Kind, c.Description
			}
		}
		return emitRead(cmd, "", []schemaEntry{e}, 1, 0, 1)
	}
	return writeSchemaJSON(s)
}

// writeSchemaJSON writes v indented, the form the docs/schema files take.
func writeSchemaJSON(v any) error {
	raw, err := marshalSchemaJSON(v)
	if err != nil {
		return err
	}
	writeBody(raw)
	return nil
}

// marshalSchemaJSON is the one encoding of a published schema: two-space
// indent and a trailing newline, so the docs/schema files diff cleanly.
func marshalSchemaJSON(v any) ([]byte, error) {
	compact, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, compact, "", "  "); err != nil {
		return nil, err
	}
	buf.WriteByte('\n')
	return buf.Bytes(), nil
}
