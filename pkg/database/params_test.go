package database

import (
	"context"
	"fmt"
	"testing"
)

func paramByName(t *testing.T, res ParamResult, location, name string) ParamView {
	t.Helper()
	for _, p := range res.Params {
		if p.Location == location && p.Name == name {
			return p
		}
	}
	t.Fatalf("no %s param %q", location, name)
	return ParamView{}
}

func TestParamsClassifyAndRedact(t *testing.T) {
	db := newTestDB(t)
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	var recs []invRec
	for i := 1; i <= 5; i++ {
		recs = append(recs, invRec{
			path: fmt.Sprintf("/users/%d/orders", i),
			params: []EmbeddedParam{
				{Name: "page", Value: fmt.Sprint(i), Type: "url"},
				{Name: "ref", Value: fmt.Sprintf("550e8400-e29b-41d4-a716-44665544000%d", i), Type: "url"},
				{Name: "email", Value: fmt.Sprintf("u%d@example.com", i), Type: "json"},
				{Name: "access_token", Value: jwt, Type: "body"},
				{Name: "sid", Value: "abc", Type: "cookie"},
			},
		})
	}
	recs = append(recs, invRec{path: "/users/9/orders", project: "proj-2",
		params: []EmbeddedParam{{Name: "leak", Value: "x", Type: "url"}}})
	seedInventory(t, db, recs)
	ctx := context.Background()

	res, err := NewQueryBuilder(db, QueryFilters{ProjectUUID: "proj-1"}).Params(ctx, ParamOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range res.Params {
		if p.Name == "leak" {
			t.Fatal("a param from another project leaked into the inventory")
		}
		if p.Template != "/users/{int}/orders" || p.EndpointID != EndpointID("https://a.test", "/users/{int}/orders") {
			t.Errorf("param %s on %q / %q", p.Name, p.Template, p.EndpointID)
		}
	}
	if page := paramByName(t, res, "query", "page"); page.DominantType != "integer" || page.Occurrences != 5 || page.DistinctValues != 5 {
		t.Errorf("page: %+v", page)
	}
	if ref := paramByName(t, res, "query", "ref"); ref.DominantType != "uuid" {
		t.Errorf("ref: %+v", ref)
	}
	email := paramByName(t, res, "json", "email")
	if email.DominantType != "email" || email.Redacted || len(email.Samples) != 3 {
		t.Errorf("email: %+v", email)
	}
	tok := paramByName(t, res, "body", "access_token")
	if tok.DominantType != "jwt" || !tok.Redacted || len(tok.Samples) != 1 || tok.Samples[0] != "<redacted>" {
		t.Errorf("access_token must be classified but redacted: %+v", tok)
	}
	if sid := paramByName(t, res, "cookie", "sid"); !sid.Redacted || sid.Samples[0] != "<redacted>" {
		t.Errorf("cookie values are redacted by default: %+v", sid)
	}
	path := paramByName(t, res, "path", "{int}@1")
	if path.After != "users" || path.DominantType != "integer" || path.Occurrences != 5 {
		t.Errorf("path param: %+v", path)
	}

	shown, err := NewQueryBuilder(db, QueryFilters{ProjectUUID: "proj-1"}).Params(ctx, ParamOptions{ShowValues: true, Locations: []string{"cookie"}})
	if err != nil {
		t.Fatal(err)
	}
	if shown.Total != 1 || shown.Params[0].Samples[0] != "abc" {
		t.Errorf("--show-values --location cookie: %+v", shown.Params)
	}

	ints, err := NewQueryBuilder(db, QueryFilters{ProjectUUID: "proj-1"}).Params(ctx, ParamOptions{Types: []string{"integer"}})
	if err != nil {
		t.Fatal(err)
	}
	if ints.Total != 2 { // page and the path id
		t.Errorf("--type integer: total=%d", ints.Total)
	}

	byEndpoint, err := NewQueryBuilder(db, QueryFilters{ProjectUUID: "proj-1"}).Params(ctx, ParamOptions{Endpoint: "/nope"})
	if err != nil {
		t.Fatal(err)
	}
	if byEndpoint.Total != 0 {
		t.Errorf("--endpoint /nope: total=%d", byEndpoint.Total)
	}
}

func TestParamsCaps(t *testing.T) {
	db := newTestDB(t)
	var recs []invRec
	for i := 0; i < paramDistinctCap+100; i++ {
		recs = append(recs, invRec{path: "/s", params: []EmbeddedParam{{Name: "q", Value: fmt.Sprintf("v%d", i), Type: "url"}}})
	}
	seedInventory(t, db, recs)
	res, err := NewQueryBuilder(db, QueryFilters{ProjectUUID: "proj-1"}).Params(context.Background(), ParamOptions{})
	if err != nil {
		t.Fatal(err)
	}
	q := paramByName(t, res, "query", "q")
	if !q.DistinctCapped || q.DistinctValues != paramDistinctCap {
		t.Errorf("distinct=%d capped=%v", q.DistinctValues, q.DistinctCapped)
	}
	if q.Classified != paramClassifyCap || q.Occurrences != int64(len(recs)) {
		t.Errorf("classified=%d occurrences=%d", q.Classified, q.Occurrences)
	}
}
