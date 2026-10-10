package httpmsg

import "testing"

func TestFindInsertionPoint(t *testing.T) {
	raw := []byte("POST /x?id=1 HTTP/1.1\r\nHost: example.com\r\nX-Token: abc\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 6\r\n\r\nid=two")
	ips, err := CreateAllInsertionPoints(raw, false)
	if err != nil {
		t.Fatal(err)
	}
	if ip := FindInsertionPoint(ips, "URL_PARAM", "id"); ip == nil || ip.BaseValue() != "1" {
		t.Fatalf("URL_PARAM:id = %v", ip)
	}
	if ip := FindInsertionPoint(ips, "body_param", "id"); ip == nil || ip.BaseValue() != "two" {
		t.Fatalf("type names match case-insensitively; BODY_PARAM:id = %v", ip)
	}
	if ip := FindInsertionPoint(ips, "", "id"); ip == nil || ip.Type() != INS_PARAM_URL {
		t.Fatalf("an empty type takes the first point with the name, got %v", ip)
	}
	if ip := FindInsertionPoint(ips, "HEADER", "x-token"); ip == nil || ip.BaseValue() != "abc" {
		t.Fatalf("header names match case-insensitively, got %v", ip)
	}
	if ip := FindInsertionPoint(ips, "COOKIE", "id"); ip != nil {
		t.Fatalf("no COOKIE:id point exists, got %v", ip)
	}
}
