// Package jsheaders implements the header object every extension API hands to
// JavaScript (ctx.request.headers, ctx.response.headers, vigolium.http.*
// responses, session responses, the yamlext JS matcher). It is a leaf package
// so both pkg/jsext and pkg/yamlext (which pkg/jsext imports) can share it.
//
// Semantics (one contract for every header object in the API):
//   - property access is case-insensitive: h["content-type"] === h["Content-Type"]
//   - Object.keys / for-in / JSON.stringify see lowercase names in first-occurrence order
//   - a repeated header reads as its values joined with ", " (RFC 9110 §5.3);
//     set-cookie, which cannot be joined, reads as its LAST value (back-compat)
//   - prototype methods (non-enumerable): get(name) string|null,
//     getAll(name) string[], has(name) bool, entries() [name, value][]
//     (original case, every occurrence, wire order), raw() original-case
//     object with last-wins duplicates (the pre-0.7 shape)
//   - assignment and delete work and change only the JS view
//
// Header names that collide with the method names (get, getAll, has, entries,
// raw — compared case-insensitively) or with Object.prototype members are not
// exposed as properties, so a hostile server cannot replace h.get with a
// string. Read them through h.get(name) / h.getAll(name) / h.entries().
package jsheaders

import (
	"sort"
	"strings"

	"github.com/grafana/sobek"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// reserved lists lowercase names that never resolve to a header through
// property access: the prototype methods plus Object.prototype members that
// scripts and sobek internals call on objects.
var reserved = map[string]struct{}{
	"get": {}, "getall": {}, "has": {}, "entries": {}, "raw": {},
	"constructor": {}, "tostring": {}, "tolocalestring": {}, "valueof": {},
	"hasownproperty": {}, "isprototypeof": {}, "propertyisenumerable": {},
	"tojson": {}, "__proto__": {},
	"__definegetter__": {}, "__definesetter__": {}, "__lookupgetter__": {}, "__lookupsetter__": {},
}

type entry struct {
	name  string // original case
	lname string // lowercase
	value string
}

// Store is the Go side of a JS header object. Export() of the JS object
// returns the *Store.
type Store struct {
	entries []entry
	// changed records lowercase names touched by JS assignment/delete, in the
	// order they were first touched, so callers that read edits back (the
	// pre_hook) apply only what the script changed.
	changed []string
}

// lower returns s lowercased, without allocating when s is already lowercase ASCII.
func lower(s string) string {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= 0x80 {
			return strings.ToLower(s)
		}
	}
	return s
}

func isReserved(lname string) bool {
	_, ok := reserved[lname]
	return ok
}

func newStore(n int) *Store { return &Store{entries: make([]entry, 0, n)} }

func (s *Store) add(name, value string) {
	s.entries = append(s.entries, entry{name: name, lname: lower(name), value: value})
}

// lookup returns the property value for a lowercase name, and whether the
// header exists. Repeated headers join with ", "; set-cookie returns the last.
func (s *Store) lookup(lname string) (string, bool) {
	first := -1
	n := 0
	for i := range s.entries {
		if s.entries[i].lname == lname {
			if first < 0 {
				first = i
			}
			n++
		}
	}
	if first < 0 {
		return "", false
	}
	if n == 1 {
		return s.entries[first].value, true
	}
	if lname == "set-cookie" {
		for i := len(s.entries) - 1; i >= 0; i-- {
			if s.entries[i].lname == lname {
				return s.entries[i].value, true
			}
		}
	}
	var b strings.Builder
	for i := first; i < len(s.entries); i++ {
		if s.entries[i].lname != lname {
			continue
		}
		if b.Len() > 0 {
			b.WriteString(", ")
		}
		b.WriteString(s.entries[i].value)
	}
	return b.String(), true
}

func (s *Store) all(lname string) []string {
	var out []string
	for i := range s.entries {
		if s.entries[i].lname == lname {
			out = append(out, s.entries[i].value)
		}
	}
	return out
}

func (s *Store) markChanged(lname string) {
	for _, c := range s.changed {
		if c == lname {
			return
		}
	}
	s.changed = append(s.changed, lname)
}

// set replaces every occurrence of name with one header at the position of
// the first occurrence (or appends it).
func (s *Store) set(name, value string) {
	lname := lower(name)
	s.markChanged(lname)
	out := s.entries[:0]
	placed := false
	for _, e := range s.entries {
		if e.lname != lname {
			out = append(out, e)
			continue
		}
		if !placed {
			out = append(out, entry{name: name, lname: lname, value: value})
			placed = true
		}
	}
	s.entries = out
	if !placed {
		s.entries = append(s.entries, entry{name: name, lname: lname, value: value})
	}
}

func (s *Store) remove(name string) {
	lname := lower(name)
	s.markChanged(lname)
	out := s.entries[:0]
	for _, e := range s.entries {
		if e.lname != lname {
			out = append(out, e)
		}
	}
	s.entries = out
}

// Entries returns every header in wire order with its original-case name.
func (s *Store) Entries() []httpmsg.HttpHeader {
	out := make([]httpmsg.HttpHeader, len(s.entries))
	for i, e := range s.entries {
		out[i] = httpmsg.HttpHeader{Name: e.name, Value: e.value}
	}
	return out
}

// Changes reports what JS assignment/delete did, in first-touched order:
// set holds the current value of every touched header that still exists
// (repeated headers joined like a property read), deleted the lowercase names
// of touched headers that no longer exist.
func (s *Store) Changes() (set []httpmsg.HttpHeader, deleted []string) {
	for _, lname := range s.changed {
		v, ok := s.lookup(lname)
		if !ok {
			deleted = append(deleted, lname)
			continue
		}
		name := lname
		for _, e := range s.entries {
			if e.lname == lname {
				name = e.name
				break
			}
		}
		set = append(set, httpmsg.HttpHeader{Name: name, Value: v})
	}
	return set, deleted
}

// dyn adapts a Store to sobek.DynamicObject.
type dyn struct {
	vm *sobek.Runtime
	s  *Store
}

func (d *dyn) Get(key string) sobek.Value {
	lname := lower(key)
	if isReserved(lname) {
		return nil
	}
	v, ok := d.s.lookup(lname)
	if !ok {
		return nil
	}
	return d.vm.ToValue(v)
}

func (d *dyn) Set(key string, val sobek.Value) bool {
	if val == nil || sobek.IsUndefined(val) || sobek.IsNull(val) {
		d.s.remove(key)
		return true
	}
	d.s.set(key, val.String())
	return true
}

func (d *dyn) Has(key string) bool {
	lname := lower(key)
	if isReserved(lname) {
		return false
	}
	for i := range d.s.entries {
		if d.s.entries[i].lname == lname {
			return true
		}
	}
	return false
}

func (d *dyn) Delete(key string) bool {
	d.s.remove(key)
	return true
}

func (d *dyn) Keys() []string {
	keys := make([]string, 0, len(d.s.entries))
outer:
	for i := range d.s.entries {
		lname := d.s.entries[i].lname
		if isReserved(lname) {
			continue
		}
		for _, k := range keys {
			if k == lname {
				continue outer
			}
		}
		keys = append(keys, lname)
	}
	return keys
}

// New returns a JS header object over an ordered header list.
func New(vm *sobek.Runtime, hs []httpmsg.HttpHeader) *sobek.Object {
	s := newStore(len(hs))
	for _, h := range hs {
		s.add(h.Name, h.Value)
	}
	return wrap(vm, s)
}

// FromMap returns a JS header object over an unordered map; names are sorted
// so the key order is deterministic.
func FromMap(vm *sobek.Runtime, m map[string]string) *sobek.Object {
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	sort.Strings(names)
	s := newStore(len(names))
	for _, k := range names {
		s.add(k, m[k])
	}
	return wrap(vm, s)
}

func wrap(vm *sobek.Runtime, s *Store) *sobek.Object {
	obj := vm.NewDynamicObject(&dyn{vm: vm, s: s})
	_ = obj.SetPrototype(prototype(vm))
	return obj
}

// FromValue returns the Store behind a JS header object, or false when v is
// not one (for example a plain object a script built itself).
func FromValue(v sobek.Value) (*Store, bool) {
	obj, ok := v.(*sobek.Object)
	if !ok || obj == nil {
		return nil, false
	}
	d, ok := obj.Export().(*dyn)
	if !ok {
		return nil, false
	}
	return d.s, true
}

// ToMap flattens a JS headers value into a name→value map for building an
// outgoing request. A header object yields original-case names with repeated
// headers joined; any other object yields its own keys, merged
// case-insensitively so that Object.assign({}, ctx.request.headers,
// {"Authorization": x}) produces one Authorization header (the later key
// wins, with its own casing).
func ToMap(vm *sobek.Runtime, v sobek.Value) map[string]string {
	out := make(map[string]string)
	if v == nil || sobek.IsUndefined(v) || sobek.IsNull(v) {
		return out
	}
	if s, ok := FromValue(v); ok {
		seen := make(map[string]string, len(s.entries))
		for _, e := range s.entries {
			if _, dup := seen[e.lname]; dup {
				continue
			}
			seen[e.lname] = e.name
			val, _ := s.lookup(e.lname)
			out[e.name] = val
		}
		return out
	}
	obj := v.ToObject(vm)
	byLower := make(map[string]string)
	for _, key := range obj.Keys() {
		lk := lower(key)
		if prev, ok := byLower[lk]; ok {
			delete(out, prev)
		}
		byLower[lk] = key
		out[key] = obj.Get(key).String()
	}
	return out
}

var protoSym = sobek.NewSymbol("vigolium.headers.prototype")

// prototype returns the per-runtime prototype holding the methods, creating
// and caching it on the global object under a private symbol.
func prototype(vm *sobek.Runtime) *sobek.Object {
	global := vm.GlobalObject()
	if v := global.GetSymbol(protoSym); v != nil {
		if p, ok := v.(*sobek.Object); ok {
			return p
		}
	}
	p := newPrototype(vm)
	// A frozen global (or one a script locked down) just means no caching.
	_ = global.DefineDataPropertySymbol(protoSym, p, sobek.FLAG_FALSE, sobek.FLAG_FALSE, sobek.FLAG_FALSE)
	return p
}

func newPrototype(vm *sobek.Runtime) *sobek.Object {
	p := vm.NewObject()
	this := func(call sobek.FunctionCall) *Store {
		s, ok := FromValue(call.This)
		if !ok {
			panic(vm.NewTypeError("headers method called on an object that is not a headers object"))
		}
		return s
	}
	method := func(name string, fn func(sobek.FunctionCall) sobek.Value) {
		_ = p.DefineDataProperty(name, vm.ToValue(fn), sobek.FLAG_TRUE, sobek.FLAG_TRUE, sobek.FLAG_FALSE)
	}
	method("get", func(call sobek.FunctionCall) sobek.Value {
		v, ok := this(call).lookup(lower(call.Argument(0).String()))
		if !ok {
			return sobek.Null()
		}
		return vm.ToValue(v)
	})
	method("getAll", func(call sobek.FunctionCall) sobek.Value {
		vals := this(call).all(lower(call.Argument(0).String()))
		items := make([]interface{}, len(vals))
		for i, v := range vals {
			items[i] = v
		}
		return vm.NewArray(items...)
	})
	method("has", func(call sobek.FunctionCall) sobek.Value {
		_, ok := this(call).lookup(lower(call.Argument(0).String()))
		return vm.ToValue(ok)
	})
	method("entries", func(call sobek.FunctionCall) sobek.Value {
		s := this(call)
		items := make([]interface{}, len(s.entries))
		for i, e := range s.entries {
			items[i] = vm.NewArray(e.name, e.value)
		}
		return vm.NewArray(items...)
	})
	method("raw", func(call sobek.FunctionCall) sobek.Value {
		s := this(call)
		obj := vm.NewObject()
		for _, e := range s.entries {
			_ = obj.Set(e.name, e.value)
		}
		return obj
	})
	return p
}
