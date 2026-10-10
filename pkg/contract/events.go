package contract

import (
	"fmt"
	"reflect"

	"github.com/invopop/jsonschema"
)

// EventFields is one event type's row of the field table: which payload keys
// a line of that type always carries and which it may carry. The spine (see
// SetEventPayload) is implied.
type EventFields struct {
	Required    []string
	Optional    []string
	Description string
}

var (
	eventPayload any
	eventVersion int
	eventSpine   []string
	eventTypes   []string
	eventTable   = map[string]EventFields{}
)

// SetEventPayload names the Go type every event line marshals from (one
// struct, omitempty past the spine), the version carried in "v", and the spine
// keys every line carries whatever its type.
func SetEventPayload(payload any, version int, spine []string) {
	mu.Lock()
	defer mu.Unlock()
	eventPayload, eventVersion, eventSpine = payload, version, append([]string(nil), spine...)
}

// RegisterEvent records one event type's fields. Registration order is the
// order `vigolium schema event` lists them in.
func RegisterEvent(typ string, f EventFields) {
	mu.Lock()
	defer mu.Unlock()
	if _, dup := eventTable[typ]; dup {
		panic(fmt.Sprintf("contract: event %q registered twice", typ))
	}
	eventTable[typ] = f
	eventTypes = append(eventTypes, typ)
}

// EventTypes lists the registered event types in registration order.
func EventTypes() []string {
	mu.RLock()
	defer mu.RUnlock()
	return append([]string(nil), eventTypes...)
}

// LookupEvent returns one event type's field table.
func LookupEvent(typ string) (EventFields, bool) {
	mu.RLock()
	defer mu.RUnlock()
	f, ok := eventTable[typ]
	return f, ok
}

// EventSchema builds the schema of one event type's line.
func EventSchema(typ string) (*Schema, error) {
	b := newBuilder()
	s, err := b.eventObject(typ)
	if err != nil {
		return nil, err
	}
	return b.root(s, "vigolium --events "+typ, s.Description), nil
}

// EventsSchema builds the schema of any --events line: oneOf the per-type
// schemas, each pinned by its "type" const.
func EventsSchema() (*Schema, error) {
	b := newBuilder()
	root := &Schema{Description: "One line of `vigolium scan --events ndjson`; `type` selects the shape."}
	for _, typ := range EventTypes() {
		s, err := b.eventObject(typ)
		if err != nil {
			return nil, err
		}
		name := "event." + typ
		b.defs[name] = s
		root.OneOf = append(root.OneOf, &Schema{Ref: "#/$defs/" + name})
	}
	return b.root(root, "vigolium --events", root.Description), nil
}

// eventObject is one event type's object schema.
func (b *builder) eventObject(typ string) (*Schema, error) {
	mu.RLock()
	payload, version, spine := eventPayload, eventVersion, eventSpine
	f, ok := eventTable[typ]
	mu.RUnlock()
	if payload == nil {
		return nil, fmt.Errorf("contract: no event payload is registered")
	}
	if !ok {
		return nil, fmt.Errorf("contract: no event type %q is registered", typ)
	}
	if reflect.TypeOf(payload).Kind() != reflect.Struct {
		return nil, fmt.Errorf("contract: event payload must be a struct, got %T", payload)
	}
	// A fresh reflection each time: the property schemas are shared by
	// pointer, and the type const below must not leak into another type.
	all := b.objectFor(payload)
	allowed := map[string]bool{}
	for _, k := range spine {
		allowed[k] = true
	}
	for _, k := range f.Required {
		allowed[k] = true
	}
	for _, k := range f.Optional {
		allowed[k] = true
	}
	known := map[string]bool{}
	for _, k := range propertyNames(all) {
		known[k] = true
	}
	for k := range allowed {
		if !known[k] {
			return nil, fmt.Errorf("contract: event %q lists %q, which the payload does not carry", typ, k)
		}
	}

	s := &Schema{
		Type:                 "object",
		Description:          f.Description,
		Properties:           jsonschema.NewProperties(),
		AdditionalProperties: jsonschema.FalseSchema,
	}
	// Payload field order, so a schema reads in wire order.
	for p := all.Properties.Oldest(); p != nil; p = p.Next() {
		if allowed[p.Key] {
			s.Properties.Set(p.Key, p.Value)
		}
	}
	s.Properties.Set("type", constSchema("string", typ))
	if _, ok := s.Properties.Get("v"); ok {
		s.Properties.Set("v", constSchema("integer", version))
	}
	for _, k := range spine {
		s.Required = appendUnique(s.Required, k)
	}
	for _, k := range f.Required {
		s.Required = appendUnique(s.Required, k)
	}
	return s, nil
}
