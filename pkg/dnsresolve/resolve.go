// Package dnsresolve answers DNS questions for one name at a time: the record
// types `vigolium dns` reports, from the system resolver or the resolvers the
// caller names. Resolution only — no zone transfer, no brute force.
package dnsresolve

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Types are the record types Resolve understands, in report order.
var Types = []string{"a", "aaaa", "cname", "mx", "ns", "txt", "soa", "caa"}

var qtypes = map[string]uint16{
	"a": dns.TypeA, "aaaa": dns.TypeAAAA, "cname": dns.TypeCNAME, "mx": dns.TypeMX,
	"ns": dns.TypeNS, "txt": dns.TypeTXT, "soa": dns.TypeSOA, "caa": dns.TypeCAA,
}

// ParseTypes validates a type list ("a,mx"); empty means every type.
func ParseTypes(in []string) ([]string, error) {
	if len(in) == 0 {
		return Types, nil
	}
	var out []string
	seen := map[string]bool{}
	for _, raw := range in {
		for _, t := range strings.Split(raw, ",") {
			t = strings.ToLower(strings.TrimSpace(t))
			if t == "" || seen[t] {
				continue
			}
			if _, ok := qtypes[t]; !ok {
				return nil, fmt.Errorf("unknown record type %q (want %s)", t, strings.Join(Types, ", "))
			}
			seen[t] = true
			out = append(out, t)
		}
	}
	return out, nil
}

// Record is one answer record.
type Record struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	TTL   uint32 `json:"ttl"`
	Value string `json:"value"`
}

// Answer is everything resolved for one name.
type Answer struct {
	Name     string   `json:"name"`
	Resolver string   `json:"resolver"`
	A        []string `json:"a,omitempty"`
	AAAA     []string `json:"aaaa,omitempty"`
	CNAME    []string `json:"cname,omitempty"`
	MX       []string `json:"mx,omitempty"`
	NS       []string `json:"ns,omitempty"`
	TXT      []string `json:"txt,omitempty"`
	SOA      []string `json:"soa,omitempty"`
	CAA      []string `json:"caa,omitempty"`
	// Records is every answer record, for a reader that wants TTLs.
	Records []Record `json:"records"`
	// Rcode is the response code of the address query ("NOERROR", "NXDOMAIN").
	Rcode string `json:"rcode"`
	// Errors names the record types whose query failed outright (timeout,
	// refused); an empty answer is not an error.
	Errors map[string]string `json:"errors,omitempty"`
}

// Resolver resolves names against fixed servers.
type Resolver struct {
	Servers []string // host:port
	Timeout time.Duration
}

// New returns a Resolver for servers, or the system's when servers is empty.
func New(servers []string, timeout time.Duration) (*Resolver, error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if len(servers) == 0 {
		cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil || len(cfg.Servers) == 0 {
			return nil, errors.New("no system resolver found in /etc/resolv.conf; pass --resolver host[:port]")
		}
		for _, s := range cfg.Servers {
			servers = append(servers, net.JoinHostPort(s, cfg.Port))
		}
	}
	out := make([]string, 0, len(servers))
	for _, s := range servers {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(s); err != nil {
			s = net.JoinHostPort(strings.Trim(s, "[]"), "53")
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil, errors.New("no resolver given")
	}
	return &Resolver{Servers: out, Timeout: timeout}, nil
}

// Resolve queries name for each type. CNAME records met while resolving A and
// AAAA are reported as the CNAME chain.
func (r *Resolver) Resolve(ctx context.Context, name string, types []string) Answer {
	fqdn := dns.Fqdn(strings.ToLower(strings.TrimSpace(name)))
	ans := Answer{Name: strings.TrimSuffix(fqdn, "."), Resolver: r.Servers[0], Records: []Record{}}
	seen := map[string]bool{}
	add := func(rec Record, into *[]string) {
		key := rec.Type + "|" + rec.Value
		if !seen[key] {
			seen[key] = true
			*into = append(*into, rec.Value)
		}
		ans.Records = append(ans.Records, rec)
	}
	for _, t := range types {
		msg, server, err := r.exchange(ctx, fqdn, qtypes[t])
		if err != nil {
			if ans.Errors == nil {
				ans.Errors = map[string]string{}
			}
			ans.Errors[t] = err.Error()
			continue
		}
		ans.Resolver = server
		if t == "a" || ans.Rcode == "" {
			ans.Rcode = dns.RcodeToString[msg.Rcode]
		}
		if msg.Rcode == dns.RcodeNameError {
			// The name does not exist; every other type would say the same.
			break
		}
		for _, rr := range msg.Answer {
			h := rr.Header()
			rec := Record{Name: strings.TrimSuffix(h.Name, "."), TTL: h.Ttl}
			switch v := rr.(type) {
			case *dns.A:
				rec.Type, rec.Value = "A", v.A.String()
				add(rec, &ans.A)
			case *dns.AAAA:
				rec.Type, rec.Value = "AAAA", v.AAAA.String()
				add(rec, &ans.AAAA)
			case *dns.CNAME:
				rec.Type, rec.Value = "CNAME", strings.TrimSuffix(v.Target, ".")
				add(rec, &ans.CNAME)
			case *dns.MX:
				rec.Type, rec.Value = "MX", strconv.Itoa(int(v.Preference))+" "+strings.TrimSuffix(v.Mx, ".")
				add(rec, &ans.MX)
			case *dns.NS:
				rec.Type, rec.Value = "NS", strings.TrimSuffix(v.Ns, ".")
				add(rec, &ans.NS)
			case *dns.TXT:
				rec.Type, rec.Value = "TXT", strings.Join(v.Txt, "")
				add(rec, &ans.TXT)
			case *dns.SOA:
				rec.Type = "SOA"
				rec.Value = fmt.Sprintf("%s %s %d %d %d %d %d", strings.TrimSuffix(v.Ns, "."), strings.TrimSuffix(v.Mbox, "."),
					v.Serial, v.Refresh, v.Retry, v.Expire, v.Minttl)
				add(rec, &ans.SOA)
			case *dns.CAA:
				rec.Type, rec.Value = "CAA", fmt.Sprintf("%d %s %s", v.Flag, v.Tag, v.Value)
				add(rec, &ans.CAA)
			}
		}
	}
	return ans
}

// exchange sends one question to each server in turn until one answers,
// retrying over TCP when the UDP answer is truncated.
func (r *Resolver) exchange(ctx context.Context, fqdn string, qtype uint16) (*dns.Msg, string, error) {
	m := new(dns.Msg)
	m.SetQuestion(fqdn, qtype)
	m.RecursionDesired = true
	m.SetEdns0(4096, false)
	var lastErr error
	udp := &dns.Client{Timeout: r.Timeout}
	for _, server := range r.Servers {
		in, _, err := udp.ExchangeContext(ctx, m, server)
		if err == nil && in != nil && in.Truncated {
			tcp := &dns.Client{Net: "tcp", Timeout: r.Timeout}
			in, _, err = tcp.ExchangeContext(ctx, m, server)
		}
		if err == nil && in != nil {
			return in, server, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no answer")
	}
	return nil, "", lastErr
}
