package dnsresolve

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// startServer runs a UDP DNS server on 127.0.0.1 answering from zone, and
// returns its address.
func startServer(t *testing.T, zone map[uint16][]string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		if q.Name != "app.example.test." {
			m.Rcode = dns.RcodeNameError
			_ = w.WriteMsg(m)
			return
		}
		for _, line := range zone[q.Qtype] {
			rr, err := dns.NewRR(line)
			if err == nil {
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

func TestResolveEveryType(t *testing.T) {
	addr := startServer(t, map[uint16][]string{
		dns.TypeA:    {"app.example.test. 60 IN CNAME edge.example.test.", "edge.example.test. 60 IN A 192.0.2.10"},
		dns.TypeAAAA: {"app.example.test. 60 IN AAAA 2001:db8::1"},
		dns.TypeMX:   {"app.example.test. 300 IN MX 10 mail.example.test."},
		dns.TypeNS:   {"app.example.test. 300 IN NS ns1.example.test."},
		dns.TypeTXT:  {`app.example.test. 300 IN TXT "v=spf1 -all"`},
		dns.TypeSOA:  {"app.example.test. 300 IN SOA ns1.example.test. hostmaster.example.test. 7 3600 600 86400 60"},
		dns.TypeCAA:  {`app.example.test. 300 IN CAA 0 issue "letsencrypt.org"`},
	})
	r, err := New([]string{addr}, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ans := r.Resolve(context.Background(), "App.Example.Test", Types)
	check := func(name string, got []string, want string) {
		t.Helper()
		if len(got) != 1 || got[0] != want {
			t.Errorf("%s = %v, want [%s]", name, got, want)
		}
	}
	check("a", ans.A, "192.0.2.10")
	check("cname", ans.CNAME, "edge.example.test")
	check("aaaa", ans.AAAA, "2001:db8::1")
	check("mx", ans.MX, "10 mail.example.test")
	check("ns", ans.NS, "ns1.example.test")
	check("txt", ans.TXT, "v=spf1 -all")
	check("soa", ans.SOA, "ns1.example.test hostmaster.example.test 7 3600 600 86400 60")
	check("caa", ans.CAA, "0 issue letsencrypt.org")
	if ans.Rcode != "NOERROR" || ans.Name != "app.example.test" || len(ans.Records) < 8 {
		t.Errorf("answer = %+v", ans)
	}

	nx := r.Resolve(context.Background(), "missing.example.test", []string{"a"})
	if nx.Rcode != "NXDOMAIN" || len(nx.A) != 0 {
		t.Errorf("nxdomain answer = %+v", nx)
	}
}

func TestParseTypes(t *testing.T) {
	got, err := ParseTypes([]string{"a,MX", "a"})
	if err != nil || len(got) != 2 || got[1] != "mx" {
		t.Fatalf("ParseTypes = %v %v", got, err)
	}
	if _, err := ParseTypes([]string{"axfr"}); err == nil {
		t.Error("axfr is not a resolution type")
	}
}
