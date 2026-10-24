package cli

import (
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeDNSServer answers app.example.test with an A, an MX and a TXT record and
// NXDOMAIN for anything else.
func fakeDNSServer(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	zone := map[uint16][]string{
		dns.TypeA:   {"app.example.test. 60 IN A 192.0.2.10"},
		dns.TypeMX:  {"app.example.test. 300 IN MX 10 mail.example.test."},
		dns.TypeTXT: {`app.example.test. 300 IN TXT "v=spf1 -all"`},
	}
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Question[0].Name != "app.example.test." {
			m.Rcode = dns.RcodeNameError
		} else {
			for _, line := range zone[r.Question[0].Qtype] {
				rr, err := dns.NewRR(line)
				require.NoError(t, err)
				m.Answer = append(m.Answer, rr)
			}
		}
		_ = w.WriteMsg(m)
	})
	srv := &dns.Server{PacketConn: pc, Handler: mux}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func TestDNSStoresAndHostsReadsBack(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the CLI")
	}
	addr := fakeDNSServer(t)
	e := newB5Env(t)

	code, stdout, stderr := e.run(t, nil, "dns", "https://App.Example.Test:8443/x", "--resolver", addr, "--ignore-scope", "-j")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	doc := oneDoc(t, stdout, stderr)
	validateRegisteredMap(t, doc)
	assert.EqualValues(t, 1, doc["stored"])
	ans := doc["items"].([]any)[0].(map[string]any)
	assert.Equal(t, "app.example.test", ans["name"])
	assert.Equal(t, []any{"192.0.2.10"}, ans["a"])
	assert.Equal(t, []any{"10 mail.example.test"}, ans["mx"])

	// Read back in a new process.
	code, stdout, stderr = e.run(t, nil, "hosts", "--has", "dns", "-j")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	doc = oneDoc(t, stdout, stderr)
	validateRegisteredMap(t, doc)
	items := doc["items"].([]any)
	require.Len(t, items, 1)
	host := items[0].(map[string]any)
	assert.Equal(t, "app.example.test", host["hostname"])
	assert.EqualValues(t, 0, host["port"])
	assert.Equal(t, []any{"v=spf1 -all"}, host["txt"])

	code, stdout, stderr = e.run(t, nil, "hosts", "--format", "tsv", "--no-header", "--fields", "hostname,a,mx")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	assert.Equal(t, "app.example.test\t192.0.2.10\t10 mail.example.test\n", stdout)

	// TSV per record.
	code, stdout, stderr = e.run(t, nil, "dns", "app.example.test", "--resolver", addr, "--ignore-scope",
		"--type", "a", "--no-store", "--format", "tsv")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	assert.Equal(t, "name\ttype\tttl\tvalue\napp.example.test\tA\t60\t192.0.2.10\n", stdout)
}

func TestDNSRefusesOutOfScopeNames(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the CLI")
	}
	home := a3Home(t, "in.example")
	code, stdout, stderr := runA3(t, home, "dns", "out.example", "--resolver", "127.0.0.1:1", "-j")
	require.Equal(t, 2, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	assert.Contains(t, stdout+stderr, "--ignore-scope")
}

func TestDigAndHostShimTranslation(t *testing.T) {
	tr, err := translateDig([]string{"+short", "MX", "example.com", "@1.1.1.1", "-p", "5353"})
	require.NoError(t, err)
	assert.Equal(t, "dns example.com --type mx --resolver 1.1.1.1:5353", strings.Join(tr.argv, " "))
	assert.NotEmpty(t, tr.notes)

	tr, err = translateDig([]string{"example.com"})
	require.NoError(t, err)
	assert.Equal(t, "dns example.com --type a", strings.Join(tr.argv, " "), "dig's default type is A")

	tr, err = translateDig([]string{"example.com", "ANY"})
	require.NoError(t, err)
	assert.Equal(t, "dns example.com", strings.Join(tr.argv, " "), "ANY is every type")

	_, err = translateDig([]string{"AXFR", "example.com", "@ns1.example.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "zone transfers")

	tr, err = translateHost([]string{"-t", "txt", "example.com", "8.8.8.8"})
	require.NoError(t, err)
	assert.Equal(t, "dns example.com --type txt --resolver 8.8.8.8", strings.Join(tr.argv, " "))
}
