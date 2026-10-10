package httpmsg

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

func extraPoints(t *testing.T, req string, o InsertionPointOptions, want InsertionPointType) []InsertionPoint {
	t.Helper()
	ips, err := CreateInsertionPoints([]byte(req), o)
	if err != nil {
		t.Fatal(err)
	}
	var out []InsertionPoint
	for _, ip := range ips {
		if ip.Type() == want {
			out = append(out, ip)
		}
	}
	return out
}

// requireCL asserts the built request parses and its Content-Length matches
// the body it carries.
func requireCL(t *testing.T, built []byte) []byte {
	t.Helper()
	body, err := GetBody(built)
	if err != nil {
		t.Fatalf("built request does not parse: %v\n%s", err, built)
	}
	cl, _ := GetHeaderValue(built, "Content-Length")
	if cl != strconv.Itoa(len(body)) {
		t.Fatalf("Content-Length %q does not match body length %d:\n%s", cl, len(body), built)
	}
	return body
}

func TestCreateAllInsertionPointsUnchangedByExtras(t *testing.T) {
	// The wrapper must stay byte-for-byte what it was: no name, body or
	// new-param points unless asked for.
	req := []byte("POST /a?x=1 HTTP/1.1\r\nHost: h\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 3\r\n\r\ny=2")
	all, err := CreateAllInsertionPoints(req, false)
	if err != nil {
		t.Fatal(err)
	}
	zero, err := CreateInsertionPoints(req, InsertionPointOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != len(zero) {
		t.Fatalf("wrapper built %d points, zero options %d", len(all), len(zero))
	}
	for i := range all {
		if all[i].Type() != zero[i].Type() || all[i].Name() != zero[i].Name() {
			t.Errorf("point %d differs: %s:%s vs %s:%s", i, all[i].Type(), all[i].Name(), zero[i].Type(), zero[i].Name())
		}
		switch all[i].Type() {
		case INS_PARAM_NAME_URL, INS_PARAM_NAME_BODY, INS_ENTIRE_BODY:
			t.Errorf("default set contains opt-in type %s", all[i].Type())
		}
	}
}

func TestParamNameInsertionPointRenamesQueryParam(t *testing.T) {
	ips := extraPoints(t, "GET /a?id=1&b=2 HTTP/1.1\r\nHost: h\r\n\r\n", InsertionPointOptions{ParamNames: true}, INS_PARAM_NAME_URL)
	if len(ips) != 2 {
		t.Fatalf("want 2 URL name points, got %d", len(ips))
	}
	if ips[0].Name() != "id" || ips[0].BaseValue() != "id" {
		t.Errorf("name/base = %q/%q", ips[0].Name(), ips[0].BaseValue())
	}
	built := string(ips[0].BuildRequest([]byte("x y")))
	if !strings.HasPrefix(built, "GET /a?x+y=1&b=2 HTTP/1.1") && !strings.HasPrefix(built, "GET /a?x%20y=1&b=2 HTTP/1.1") {
		t.Errorf("rename not spliced over the name:\n%s", built)
	}
}

func TestParamNameInsertionPointRenamesBodyParamAndRefreshesCL(t *testing.T) {
	req := "POST /a HTTP/1.1\r\nHost: h\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 7\r\n\r\nuser=al"
	ips := extraPoints(t, req, InsertionPointOptions{ParamNames: true}, INS_PARAM_NAME_BODY)
	if len(ips) != 1 {
		t.Fatalf("want 1 body name point, got %d", len(ips))
	}
	body := requireCL(t, ips[0].BuildRequest([]byte("username")))
	if string(body) != "username=al" {
		t.Errorf("body = %q", body)
	}
}

func TestEntireBodyInsertionPoint(t *testing.T) {
	req := "POST /a HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\nContent-Length: 7\r\n\r\n{\"a\":1}"
	ips := extraPoints(t, req, InsertionPointOptions{EntireBody: true}, INS_ENTIRE_BODY)
	if len(ips) != 1 {
		t.Fatalf("want 1 entire-body point, got %d", len(ips))
	}
	if ips[0].BaseValue() != `{"a":1}` {
		t.Errorf("base = %q", ips[0].BaseValue())
	}
	body := requireCL(t, ips[0].BuildRequest([]byte("<x>longer payload</x>")))
	if string(body) != "<x>longer payload</x>" {
		t.Errorf("body = %q", body)
	}

	// No body, no point: there is nothing to replace.
	if got := extraPoints(t, "GET / HTTP/1.1\r\nHost: h\r\n\r\n", InsertionPointOptions{EntireBody: true}, INS_ENTIRE_BODY); len(got) != 0 {
		t.Errorf("bodiless request produced %d entire-body points", len(got))
	}
}

func newParamPoint(t *testing.T, req string, loc NewParamLocation) *NewParamInsertionPoint {
	t.Helper()
	ips, err := CreateInsertionPoints([]byte(req), InsertionPointOptions{NewParam: &NewParamSpec{Location: loc, Value: "c4n"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range ips {
		if np, ok := ip.(*NewParamInsertionPoint); ok {
			return np
		}
	}
	t.Fatal("no new-param point built")
	return nil
}

func TestNewParamQueryWithAndWithoutExistingQuery(t *testing.T) {
	np := newParamPoint(t, "GET /a HTTP/1.1\r\nHost: h\r\n\r\n", NewParamQuery)
	if np.Type() != INS_PARAM_NAME_URL || np.Name() != "<new>" {
		t.Errorf("type/name = %s/%s", np.Type(), np.Name())
	}
	if got := string(np.BuildRequest([]byte("debug"))); !strings.HasPrefix(got, "GET /a?debug=c4n HTTP/1.1") {
		t.Errorf("no-query append:\n%s", got)
	}
	np = newParamPoint(t, "GET /a?id=1 HTTP/1.1\r\nHost: h\r\n\r\n", NewParamQuery)
	built := np.BuildRequest([]byte("debug"))
	if !strings.HasPrefix(string(built), "GET /a?id=1&debug=c4n HTTP/1.1") {
		t.Errorf("existing-query append:\n%s", built)
	}
	off := np.PayloadOffsets([]byte("debug"))
	if len(off) != 2 || string(built[off[0]:off[1]]) != "debug" {
		t.Errorf("offsets %v do not point at the name", off)
	}
}

func TestNewParamFormBody(t *testing.T) {
	np := newParamPoint(t, "POST /a HTTP/1.1\r\nHost: h\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 3\r\n\r\na=1", NewParamBody)
	if np.Type() != INS_PARAM_NAME_BODY {
		t.Errorf("type = %s", np.Type())
	}
	if body := requireCL(t, np.BuildRequest([]byte("role"))); string(body) != "a=1&role=c4n" {
		t.Errorf("body = %q", body)
	}

	// Empty body: the field becomes the body, and a Content-Type is supplied so
	// the server parses it as a form.
	np = newParamPoint(t, "POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\n", NewParamBody)
	built := np.BuildRequest([]byte("role"))
	if body := requireCL(t, built); string(body) != "role=c4n" {
		t.Errorf("body = %q", body)
	}
	if ct, _ := GetContentType(built); !strings.Contains(ct, "x-www-form-urlencoded") {
		t.Errorf("content-type = %q", ct)
	}
}

func TestNewParamJSONBody(t *testing.T) {
	np := newParamPoint(t, "POST /a HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\nContent-Length: 7\r\n\r\n{\"a\":1}", NewParamJSON)
	body := requireCL(t, np.BuildRequest([]byte(`is"admin`)))
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("not JSON: %q (%v)", body, err)
	}
	if m["a"] != float64(1) || m[`is"admin`] != "c4n" {
		t.Errorf("members = %v", m)
	}

	// Empty JSON object and empty body both become a one-member object.
	for _, b := range []string{"{}", ""} {
		req := "POST /a HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(b)) + "\r\n\r\n" + b
		np := newParamPoint(t, req, NewParamJSON)
		if body := requireCL(t, np.BuildRequest([]byte("k"))); !bytes.Equal(body, []byte(`{"k":"c4n"}`)) {
			t.Errorf("body %q → %q", b, body)
		}
	}
}

func TestResolveNewParamLocationAuto(t *testing.T) {
	for _, tc := range []struct {
		req  string
		want NewParamLocation
	}{
		{"GET /a HTTP/1.1\r\nHost: h\r\n\r\n", NewParamQuery},
		{"POST /a HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}", NewParamJSON},
		{"POST /a HTTP/1.1\r\nHost: h\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 3\r\n\r\na=1", NewParamBody},
	} {
		if got := ResolveNewParamLocation([]byte(tc.req), NewParamAuto); got != tc.want {
			t.Errorf("%q → %q, want %q", tc.req[:20], got, tc.want)
		}
	}
}

func TestExtraPointsSortAfterParamValues(t *testing.T) {
	// Name and body points must never be tested ahead of the parameter values
	// whole-request callers front-load.
	req := "POST /a?q=1 HTTP/1.1\r\nHost: h\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 3\r\n\r\nb=2"
	ips, err := CreateInsertionPoints([]byte(req), InsertionPointOptions{ParamNames: true, EntireBody: true, NewParam: &NewParamSpec{}})
	if err != nil {
		t.Fatal(err)
	}
	seenExtra := false
	for _, ip := range ips {
		switch ip.Type() {
		case INS_PARAM_NAME_URL, INS_PARAM_NAME_BODY, INS_ENTIRE_BODY:
			seenExtra = true
		case INS_PARAM_URL, INS_PARAM_BODY:
			if seenExtra {
				t.Fatalf("param value %s:%s sorted after an opt-in point", ip.Type(), ip.Name())
			}
		}
	}
	if !seenExtra {
		t.Fatal("no opt-in points built")
	}
}
