package oast

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/oast/oastclass"
)

// Offline ingestion of callbacks logged by the operator's own OAST endpoint
// (`vigolium oast ingest`). A scan run with a {nonce} oast_url persists every
// planted payload's context to oast_payloads; ingest finds those nonces in the
// host or path of each logged callback, restores the context, and reports the
// callback through the same path the live interactsh poller uses
// (Service.reportCorrelated), saving the finding to the scan that planted it.

// Ingest formats accepted by ParseCallbacks.
const (
	// FormatInteractshJSON is interactsh-client -json output: one interaction
	// object per line (or a JSON array of them).
	FormatInteractshJSON = "interactsh-json"
	// FormatCollaboratorJSON is Burp Collaborator polling output: the
	// {"responses":[…]} document, a bare array, or one interaction per line.
	FormatCollaboratorJSON = "collaborator-json"
	// FormatRawLog is any line-oriented log (web server access log, DNS query
	// log): each line that carries a known nonce is one callback.
	FormatRawLog = "raw-log"
)

// IngestFormats lists the accepted ingest formats.
func IngestFormats() []string {
	return []string{FormatInteractshJSON, FormatCollaboratorJSON, FormatRawLog}
}

// Callback is one parsed out-of-band interaction and the places its nonce may
// sit: the callback host, and host+path for an HTTP request.
type Callback struct {
	Interaction server.Interaction
	// Where holds the host / host+path strings searched for a nonce, most
	// specific last. For a raw-log line it is the line itself.
	Where []string
}

// ParseOptions tunes ParseCallbacks.
type ParseOptions struct {
	// Protocol overrides the protocol of raw-log callbacks (http, dns, smtp…).
	// Empty means guess from the line.
	Protocol string
}

// ParseCallbacks reads callbacks in the named format from r.
func ParseCallbacks(r io.Reader, format string, opts ParseOptions) ([]Callback, error) {
	switch format {
	case FormatInteractshJSON:
		return parseInteractshJSON(r)
	case FormatCollaboratorJSON:
		return parseCollaboratorJSON(r)
	case FormatRawLog:
		return parseRawLog(r, opts.Protocol)
	default:
		return nil, fmt.Errorf("unknown ingest format %q (want one of: %s)", format, strings.Join(IngestFormats(), ", "))
	}
}

// decodeJSONStream calls fn for every object in r, which holds either one JSON
// array of objects or a sequence of objects (NDJSON or concatenated).
func decodeJSONStream(r io.Reader, fn func(json.RawMessage) error) error {
	br := bufio.NewReader(r)
	for {
		b, err := br.Peek(1)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if b[0] == ' ' || b[0] == '\t' || b[0] == '\r' || b[0] == '\n' {
			_, _ = br.ReadByte()
			continue
		}
		break
	}
	dec := json.NewDecoder(br)
	first, _ := br.Peek(1)
	if first[0] == '[' {
		var arr []json.RawMessage
		if err := dec.Decode(&arr); err != nil {
			return fmt.Errorf("decoding JSON array: %w", err)
		}
		for _, raw := range arr {
			if err := fn(raw); err != nil {
				return err
			}
		}
		return nil
	}
	for n := 1; ; n++ {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err == io.EOF {
			return nil
		} else if err != nil {
			return fmt.Errorf("decoding JSON value %d: %w", n, err)
		}
		if err := fn(raw); err != nil {
			return err
		}
	}
}

func parseInteractshJSON(r io.Reader) ([]Callback, error) {
	var out []Callback
	err := decodeJSONStream(r, func(raw json.RawMessage) error {
		var in server.Interaction
		if err := json.Unmarshal(raw, &in); err != nil {
			return fmt.Errorf("decoding interactsh interaction: %w", err)
		}
		if in.Protocol == "" && in.UniqueID == "" && in.FullId == "" {
			return nil
		}
		in.Protocol = strings.ToLower(in.Protocol)
		where := []string{in.FullId, in.UniqueID}
		where = append(where, httpRequestLocations(in.RawRequest)...)
		out = append(out, Callback{Interaction: in, Where: where})
		return nil
	})
	return out, err
}

// collaboratorInteraction covers the Burp Collaborator polling format
// (protocol / interactionString / clientIp / time / data) and the Montoya API
// field names (type / id / clientIp / timeStamp / dnsDetails / httpDetails).
type collaboratorInteraction struct {
	Protocol          string          `json:"protocol"`
	Type              string          `json:"type"`
	InteractionString string          `json:"interactionString"`
	ID                string          `json:"id"`
	ClientIP          string          `json:"clientIp"`
	Time              json.RawMessage `json:"time"`
	TimeStamp         json.RawMessage `json:"timeStamp"`
	Data              struct {
		SubDomain    string          `json:"subDomain"`
		Type         json.RawMessage `json:"type"`
		RawRequest   string          `json:"rawRequest"`
		Request      string          `json:"request"`
		Response     string          `json:"response"`
		Conversation string          `json:"conversation"`
		Message      string          `json:"message"`
	} `json:"data"`
	DNSDetails *struct {
		Query     string `json:"query"`
		QueryType string `json:"queryType"`
	} `json:"dnsDetails"`
	HTTPDetails *struct {
		Protocol        string `json:"protocol"`
		RequestResponse struct {
			Request  string `json:"request"`
			Response string `json:"response"`
		} `json:"requestResponse"`
	} `json:"httpDetails"`
}

func parseCollaboratorJSON(r io.Reader) ([]Callback, error) {
	var out []Callback
	add := func(raw json.RawMessage) error {
		var ci collaboratorInteraction
		if err := json.Unmarshal(raw, &ci); err != nil {
			return fmt.Errorf("decoding collaborator interaction: %w", err)
		}
		if cb, ok := ci.callback(); ok {
			out = append(out, cb)
		}
		return nil
	}
	err := decodeJSONStream(r, func(raw json.RawMessage) error {
		// The polling document wraps the interactions in "responses".
		var doc struct {
			Responses []json.RawMessage `json:"responses"`
		}
		if bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) && json.Unmarshal(raw, &doc) == nil && doc.Responses != nil {
			for _, item := range doc.Responses {
				if err := add(item); err != nil {
					return err
				}
			}
			return nil
		}
		return add(raw)
	})
	return out, err
}

// dnsTypeNames maps the numeric DNS query types Collaborator reports.
var dnsTypeNames = map[int]string{1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}

func (ci collaboratorInteraction) callback() (Callback, bool) {
	proto := strings.ToLower(firstNonEmpty(ci.Protocol, ci.Type))
	id := firstNonEmpty(ci.InteractionString, ci.ID)
	if proto == "" && id == "" {
		return Callback{}, false
	}
	in := server.Interaction{
		Protocol:      proto,
		UniqueID:      id,
		FullId:        firstNonEmpty(ci.Data.SubDomain, id),
		RemoteAddress: ci.ClientIP,
		Timestamp:     parseFlexibleTime(firstNonEmptyRaw(ci.Time, ci.TimeStamp)),
	}
	where := []string{id, ci.Data.SubDomain}
	switch {
	case ci.DNSDetails != nil:
		in.FullId = firstNonEmpty(ci.DNSDetails.Query, in.FullId)
		in.QType = ci.DNSDetails.QueryType
		where = append(where, ci.DNSDetails.Query)
	case len(ci.Data.Type) > 0:
		if n, err := strconv.Atoi(strings.Trim(string(ci.Data.Type), `"`)); err == nil {
			in.QType = dnsTypeNames[n]
		}
	}
	req := firstNonEmpty(decodeMaybeBase64(ci.Data.Request), decodeMaybeBase64(ci.Data.RawRequest))
	resp := decodeMaybeBase64(ci.Data.Response)
	if ci.HTTPDetails != nil {
		req = firstNonEmpty(decodeMaybeBase64(ci.HTTPDetails.RequestResponse.Request), req)
		resp = firstNonEmpty(decodeMaybeBase64(ci.HTTPDetails.RequestResponse.Response), resp)
		if p := strings.ToLower(ci.HTTPDetails.Protocol); p == "http" || p == "https" {
			in.Protocol = p
		}
	}
	if req == "" {
		req = firstNonEmpty(decodeMaybeBase64(ci.Data.Conversation), decodeMaybeBase64(ci.Data.Message))
	}
	in.RawRequest, in.RawResponse = req, resp
	if in.Protocol == "http" || in.Protocol == "https" {
		where = append(where, httpRequestLocations(req)...)
	}
	return Callback{Interaction: in, Where: where}, true
}

// decodeMaybeBase64 decodes s when it is standard base64 (Collaborator encodes
// raw requests), returning it unchanged otherwise.
func decodeMaybeBase64(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return string(b)
	}
	return s
}

var (
	requestLineRe = regexp.MustCompile(`\b(GET|POST|PUT|HEAD|OPTIONS|DELETE|PATCH|CONNECT|TRACE|PROPFIND)\s+\S+\s+HTTP/[0-9.]+`)
	dnsLineRe     = regexp.MustCompile(`(?i)\b(dns|query|qtype|IN\s+(A|AAAA|CNAME|TXT|MX|NS))\b`)
	smtpLineRe    = regexp.MustCompile(`(?i)\b(smtp|MAIL FROM|RCPT TO)\b`)
	ipv4Re        = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	rfc3339Re     = regexp.MustCompile(`\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?`)
	clfTimeRe     = regexp.MustCompile(`\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]`)
)

// parseRawLog reads one callback per non-empty line. The nonce is searched in
// the whole line; the protocol is protocol when given, else guessed (an HTTP
// request line → http, SMTP verbs → smtp, otherwise dns, the weakest claim).
func parseRawLog(r io.Reader, protocol string) ([]Callback, error) {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	var out []Callback
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		proto := protocol
		if proto == "" {
			switch {
			case requestLineRe.MatchString(line):
				proto = "http"
			case smtpLineRe.MatchString(line):
				proto = "smtp"
			case dnsLineRe.MatchString(line):
				proto = "dns"
			default:
				proto = "dns"
			}
		}
		out = append(out, Callback{
			Interaction: server.Interaction{
				Protocol:      proto,
				RawRequest:    line,
				RemoteAddress: ipv4Re.FindString(line),
				Timestamp:     logLineTime(line),
			},
			Where: []string{line},
		})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading log: %w", err)
	}
	return out, nil
}

// logLineTime extracts an RFC 3339 or Common Log Format timestamp from a log
// line; zero when there is none.
func logLineTime(line string) time.Time {
	if m := clfTimeRe.FindStringSubmatch(line); m != nil {
		if t, err := time.Parse("02/Jan/2006:15:04:05 -0700", m[1]); err == nil {
			return t.UTC()
		}
	}
	if m := rfc3339Re.FindString(line); m != "" {
		for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05Z07:00", "2006-01-02T15:04:05", "2006-01-02 15:04:05"} {
			if t, err := time.Parse(layout, m); err == nil {
				return t.UTC()
			}
		}
	}
	return time.Time{}
}

// parseFlexibleTime reads a timestamp given as epoch milliseconds/seconds
// (number or string) or as an RFC 3339 string; zero when it cannot.
func parseFlexibleTime(raw json.RawMessage) time.Time {
	s := strings.Trim(strings.TrimSpace(string(raw)), `"`)
	if s == "" || s == "null" {
		return time.Time{}
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		if n > 1e12 {
			return time.UnixMilli(n).UTC()
		}
		return time.Unix(n, 0).UTC()
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC()
	}
	return time.Time{}
}

// httpRequestLocations returns host and host+path of a raw HTTP request (from
// its Host header and request target), the places a {nonce} template puts the
// nonce.
func httpRequestLocations(raw string) []string {
	if raw == "" {
		return nil
	}
	head, _, _ := strings.Cut(raw, "\r\n\r\n")
	head, _, _ = strings.Cut(head, "\n\n")
	lines := strings.Split(head, "\n")
	var host, target string
	if f := strings.Fields(strings.TrimSpace(lines[0])); len(f) >= 2 {
		target = f[1]
	}
	for _, l := range lines[1:] {
		name, value, ok := strings.Cut(strings.TrimSpace(l), ":")
		if ok && strings.EqualFold(strings.TrimSpace(name), "host") {
			host = strings.TrimSpace(value)
			break
		}
	}
	if i := strings.Index(target, "://"); i >= 0 {
		// Absolute-form target: it names the host itself.
		target = target[i+len("://"):]
		return []string{host, target}
	}
	return []string{host, host + target}
}

// nonceRunRe finds runs of the nonce alphabet (xid: 20 chars of [0-9a-v]).
var nonceRunRe = regexp.MustCompile(`[0-9a-v]{20,}`)

// nonceLen is the length of a minted nonce.
const nonceLen = 20

// maxNonceRun bounds the run length searched window by window, so a long
// base32-ish blob cannot fan out into thousands of lookups.
const maxNonceRun = 128

// nonceCandidates returns every substring of text that could be a minted
// nonce, in order. Text is lowercased first: DNS resolvers randomise the case
// of query names (0x20 encoding).
func nonceCandidates(text string) []string {
	var out []string
	for _, run := range nonceRunRe.FindAllString(strings.ToLower(text), -1) {
		if len(run) > maxNonceRun {
			continue
		}
		for i := 0; i+nonceLen <= len(run); i++ {
			out = append(out, run[i:i+nonceLen])
		}
	}
	return out
}

// IngestedFinding describes one finding produced by Ingest.
type IngestedFinding struct {
	Nonce       string `json:"nonce"`
	ProjectUUID string `json:"project_uuid"`
	ScanUUID    string `json:"scan_uuid,omitempty"`
	ModuleID    string `json:"module_id"`
	Class       string `json:"class,omitempty"`
	TargetURL   string `json:"target_url,omitempty"`
	Param       string `json:"param,omitempty"`
	Protocol    string `json:"protocol"`
	Severity    string `json:"severity"`
	Confidence  string `json:"confidence"`
	FindingHash string `json:"finding_hash"`
}

// IngestResult summarises an Ingest run.
type IngestResult struct {
	// Callbacks is how many callbacks were parsed.
	Callbacks int `json:"callbacks"`
	// Matched callbacks carried a nonce stored in oast_payloads.
	Matched int `json:"matched"`
	// Unmatched callbacks carried no known nonce and were ignored.
	Unmatched int `json:"unmatched"`
	// Duplicates were matched but already stored by an earlier ingest.
	Duplicates int               `json:"duplicates"`
	Findings   []IngestedFinding `json:"findings"`
}

// Ingest attributes callbacks to the payloads planted with a {nonce} oast_url
// and reports them as findings of the scans that planted them. projectUUID
// scopes the nonce lookup ("" searches every project, for a stateless
// database). Callbacks without a known nonce are ignored; callbacks already
// stored (same nonce, protocol, raw request and remote address) are skipped,
// so ingesting the same log twice adds nothing.
func Ingest(ctx context.Context, repo *database.Repository, projectUUID string, callbacks []Callback) (*IngestResult, error) {
	if repo == nil {
		return nil, fmt.Errorf("oast ingest needs a database")
	}
	res := &IngestResult{Callbacks: len(callbacks), Findings: []IngestedFinding{}}

	perCallback := make([][]string, len(callbacks))
	var all []string
	for i, cb := range callbacks {
		for _, w := range cb.Where {
			perCallback[i] = append(perCallback[i], nonceCandidates(w)...)
		}
		all = append(all, perCallback[i]...)
	}
	stored, err := repo.GetOASTPayloadsByNonce(ctx, projectUUID, all)
	if err != nil {
		return nil, err
	}

	type match struct {
		cb    Callback
		nonce string
		where string
		row   *database.OASTPayload
	}
	var matches []match
	matchedNonces := map[string]struct{}{}
	for i, cb := range callbacks {
		var m *match
		for _, cand := range perCallback[i] {
			if row, ok := stored[cand]; ok {
				m = &match{cb: cb, nonce: cand, row: row, where: locationOf(cb.Where, cand)}
				break
			}
		}
		if m == nil {
			res.Unmatched++
			continue
		}
		res.Matched++
		matches = append(matches, *m)
		matchedNonces[m.nonce] = struct{}{}
	}
	if len(matches) == 0 {
		return res, nil
	}

	// What earlier ingests already stored for these nonces: exact repeats are
	// skipped, and each nonce's strongest protocol primes the coalescing state
	// so a weaker repeat does not re-report and a stronger one upgrades.
	nonces := make([]string, 0, len(matchedNonces))
	for n := range matchedNonces {
		nonces = append(nonces, n)
	}
	prior, err := repo.ListOASTInteractionsByUniqueIDs(ctx, projectUUID, nonces)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(prior))
	for _, p := range prior {
		seen[interactionKey(p.UniqueID, p.Protocol, p.RawRequest, p.RemoteAddress)] = struct{}{}
	}

	services := map[string]*Service{}
	serviceFor := func(row *database.OASTPayload) *Service {
		key := row.ProjectUUID + "\x00" + row.ScanUUID
		if svc, ok := services[key]; ok {
			return svc
		}
		svc := &Service{repo: repo, scanUUID: row.ScanUUID, projectUUID: row.ProjectUUID}
		for _, p := range prior {
			if p.ProjectUUID == row.ProjectUUID && p.ScanUUID == row.ScanUUID {
				svc.claimEmission(p.UniqueID, p.Protocol)
			}
		}
		services[key] = svc
		return svc
	}

	for _, m := range matches {
		in := m.cb.Interaction
		in.UniqueID = m.nonce
		if in.FullId == "" {
			in.FullId = m.where
		}
		key := interactionKey(in.UniqueID, in.Protocol, in.RawRequest, in.RemoteAddress)
		if _, dup := seen[key]; dup {
			res.Duplicates++
			continue
		}
		seen[key] = struct{}{}

		pctx := payloadContextFromRow(m.row, m.where)
		svc := serviceFor(m.row)
		svc.recordInteraction(&in, pctx)
		result := svc.reportCorrelated(&in, m.nonce, pctx)
		if result == nil {
			continue
		}
		res.Findings = append(res.Findings, IngestedFinding{
			Nonce:       m.nonce,
			ProjectUUID: m.row.ProjectUUID,
			ScanUUID:    m.row.ScanUUID,
			ModuleID:    result.ModuleID,
			Class:       m.row.Class,
			TargetURL:   result.URL,
			Param:       result.FuzzingParameter,
			Protocol:    in.Protocol,
			Severity:    result.Info.Severity.String(),
			Confidence:  result.Info.Confidence.String(),
			FindingHash: result.ID(),
		})
	}
	return res, nil
}

// payloadContextFromRow restores the PayloadContext of a persisted payload.
// The human label is not stored, so the class stands in for it. callback is
// where the nonce was found (host, or host+path).
func payloadContextFromRow(row *database.OASTPayload, callback string) PayloadContext {
	cls, ok := oastclass.Parse(row.Class)
	if !ok {
		cls = oastclass.Generic
	}
	return PayloadContext{
		TargetURL:     row.TargetURL,
		ParameterName: row.Param,
		InjectionType: string(cls),
		Class:         cls,
		ModuleID:      row.ModuleID,
		RequestHash:   row.RequestHash,
		CallbackURL:   callback,
		Payload:       row.Payload,
	}
}

// locationOf returns the first of where that contains nonce (case-insensitive).
func locationOf(where []string, nonce string) string {
	for _, w := range where {
		if strings.Contains(strings.ToLower(w), nonce) {
			return w
		}
	}
	return nonce
}

// interactionKey identifies a stored callback for duplicate detection.
func interactionKey(uniqueID, protocol, rawRequest, remote string) string {
	return strings.Join([]string{uniqueID, strings.ToLower(protocol), rawRequest, remote}, "\x00")
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func firstNonEmptyRaw(vals ...json.RawMessage) json.RawMessage {
	for _, v := range vals {
		if len(v) > 0 && string(v) != "null" {
			return v
		}
	}
	return nil
}
