package httpmsg

import "testing"

func TestHostPortKey(t *testing.T) {
	cases := []struct {
		url  string
		want string
	}{
		{"http://Example.COM/a", "example.com:80"},
		{"https://example.com/a", "example.com:443"},
		{"http://example.com:8080/x?y=1", "example.com:8080"},
		{"http://[::1]:9000/", "[::1]:9000"},
	}
	for _, tc := range cases {
		rr, err := GetRawRequestFromURL(tc.url)
		if err != nil {
			t.Fatalf("GetRawRequestFromURL(%q): %v", tc.url, err)
		}
		if got := HostPortKey(rr); got != tc.want {
			t.Errorf("HostPortKey(%q) = %q, want %q", tc.url, got, tc.want)
		}
	}
	if got := HostPortKey(nil); got != "" {
		t.Errorf("HostPortKey(nil) = %q, want empty", got)
	}
}

// The breaker key must not depend on the method: a GET failure has to
// quarantine POSTs to the same host:port.
func TestHostPortKey_MethodIndependent(t *testing.T) {
	get, err := GetRawRequestFromURL("http://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	post := NewHttpRequestResponse(get.Request().WithMethod("POST"), nil)
	if get.ID() == post.ID() {
		t.Fatal("precondition: ID() should differ by method")
	}
	if HostPortKey(get) != HostPortKey(post) {
		t.Errorf("HostPortKey differs by method: %q vs %q", HostPortKey(get), HostPortKey(post))
	}
}
