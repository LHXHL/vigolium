package discovery

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/deparos/jstangle"
	"github.com/vigolium/vigolium/pkg/deparos/jstangle/clientroute"
	"go.uber.org/zap"
)

// processJSTangleCapabilityFacts connects non-legacy record families to
// discovery without conflating them with generic HTTP traffic. GraphQL HTTP
// operations become exact typed templates, routes and path literals become
// bounded navigation hints, and WS/SSE/browser-flow records remain metadata
// for protocol-aware consumers.
func (e *Engine) processJSTangleCapabilityFacts(sourceURL string, result *jstangle.ScanResult) {
	if result == nil {
		return
	}
	e.collectJSFacts(sourceURL, result)
	if e.storage != nil {
		if repo := e.storage.Extractions(); repo != nil {
			var sourceNodeID int64
			if parsed := parseURL(sourceURL); parsed != nil {
				sourceNodeID = e.getNodeIDForURL(parsed)
			}
			if err := repo.BatchStoreJSTangleCapabilityFacts(
				sourceNodeID, e.storage.SessionDBID(), sourceURL, result,
			); err != nil {
				logger.Warn("Failed to store jstangle capability facts", zap.String("source", sourceURL), zap.Error(err))
			}
		}
	}

	generated := make([]jstangle.HTTPRequestFact, 0, len(result.GraphQLOperations))
	for i := range result.GraphQLOperations {
		if request, ok := graphQLOperationRequest(&result.GraphQLOperations[i]); ok {
			if e.AddRequestFact(sourceURL, request) {
				generated = append(generated, request)
			}
		}
	}
	if e.config.JSTangle.ProtocolHandshake {
		for i := range result.WebSockets {
			if request, ok := webSocketHandshakeRequest(&result.WebSockets[i]); ok && e.AddRequestFact(sourceURL, request) {
				generated = append(generated, request)
			}
		}
		for i := range result.EventSources {
			if request, ok := eventSourceHandshakeRequest(&result.EventSources[i]); ok && e.AddRequestFact(sourceURL, request) {
				generated = append(generated, request)
			}
		}
	}
	if len(generated) > 0 {
		if parsed := parseURL(sourceURL); parsed != nil {
			e.storeJSTangleFacts(parsed, generated)
		}
	}

	for i := range result.ClientRoutes {
		route := &result.ClientRoutes[i]
		if clientroute.Skip(route.RouteType, route.Provenance.Confidence) {
			continue
		}
		if path, ok := clientRouteSeed(route); ok {
			e.AddObservedPath(path)
		}
		if route.LazyAsset != nil {
			e.processAssetFacts(e.ctx, sourceURL, nil, []jstangle.AssetReferenceFact{{
				Kind: "assetReference", ID: route.ID + "-lazy", AssetType: string(AssetDynamicImport),
				URL: *route.LazyAsset, ParentSourceURL: sourceURL, Eager: false,
				Provenance: route.Provenance,
			}})
		}
	}

	// Path literals are low-confidence hints the helper reports only when no
	// request or route consumed them; they seed the wordlist like linkfinder.
	for i := range result.PathLiterals {
		path, trusted, ok := pathLiteralSeed(&result.PathLiterals[i])
		if !ok {
			continue
		}
		if trusted {
			// Same promotion linkfinder output gets: an API-looking path is
			// fetched, and either kind survives eviction as a trusted seed.
			e.AddObservedPathTrusted(path)
			e.preserveAPIPathAsRequest(path)
			continue
		}
		e.AddObservedPath(path)
	}
}

// clientRouteSeed is the discovery path for a route fact; see
// clientroute.SeedPath, which the browser crawl's route seeds share.
func clientRouteSeed(route *jstangle.ClientRouteFact) (string, bool) {
	if route == nil {
		return "", false
	}
	fullPath := ""
	if route.FullPath != nil {
		fullPath = route.FullPath.Rendered
	}
	return clientroute.SeedPath(route.Path.Rendered, fullPath, route.Provenance.Extractor)
}

// pathLiteralKeyHint marks an object key or binding name that says the
// literal is a URL or endpoint rather than an arbitrary slash-separated value.
var pathLiteralKeyHint = regexp.MustCompile(`(?i)url|path|endpoint|api|route|href`)

// pathLiteralSeed decides how a low-confidence path literal feeds discovery.
// Only static values are used: a templated literal has no concrete path to
// seed. trusted is true when the binding name or the path itself says
// "endpoint"; those get the trusted frequency boost and API promotion.
func pathLiteralSeed(fact *jstangle.PathLiteralFact) (path string, trusted, ok bool) {
	if fact == nil || !fact.Value.Static {
		return "", false, false
	}
	path = strings.TrimSpace(fact.Value.Rendered)
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") {
		return "", false, false
	}
	return path, pathLiteralKeyHint.MatchString(fact.Key) || looksLikeAPIEndpointPath(path), true
}

func staticHeader(name, value string) jstangle.HeaderTemplate {
	return jstangle.HeaderTemplate{
		Name:  jstangle.ValueTemplate{Rendered: name, Static: true},
		Value: jstangle.ValueTemplate{Rendered: value, Static: true},
	}
}

func webSocketHandshakeRequest(fact *jstangle.WebSocketFact) (jstangle.HTTPRequestFact, bool) {
	if fact == nil || fact.URL.Rendered == "" {
		return jstangle.HTTPRequestFact{}, false
	}
	rawURL := fact.URL.Rendered
	if strings.HasPrefix(rawURL, "wss://") {
		rawURL = "https://" + strings.TrimPrefix(rawURL, "wss://")
	} else if strings.HasPrefix(rawURL, "ws://") {
		rawURL = "http://" + strings.TrimPrefix(rawURL, "ws://")
	}
	headers := []jstangle.HeaderTemplate{
		staticHeader("Connection", "Upgrade"), staticHeader("Upgrade", "websocket"),
		staticHeader("Sec-WebSocket-Version", "13"), staticHeader("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="),
	}
	if len(fact.Subprotocols) > 0 {
		headers = append(headers, staticHeader("Sec-WebSocket-Protocol", strings.Join(fact.Subprotocols, ", ")))
	}
	return jstangle.HTTPRequestFact{
		Kind: "httpRequest", ID: fact.ID + "-handshake", URL: jstangle.ValueTemplate{Rendered: rawURL, Static: fact.URL.Static, Variables: fact.URL.Variables},
		Method: jstangle.ValueTemplate{Rendered: "GET", Static: true}, Headers: headers, Client: "protocol",
		Provenance: jstangle.Provenance{Extractor: "websocket-handshake", Confidence: "high", Start: fact.Provenance.Start, Evidence: fact.Provenance.Evidence},
	}, true
}

func eventSourceHandshakeRequest(fact *jstangle.EventSourceFact) (jstangle.HTTPRequestFact, bool) {
	if fact == nil || fact.URL.Rendered == "" {
		return jstangle.HTTPRequestFact{}, false
	}
	headers := []jstangle.HeaderTemplate{staticHeader("Accept", "text/event-stream")}
	if fact.LastEventID != nil && fact.LastEventID.Static {
		headers = append(headers, staticHeader("Last-Event-ID", fact.LastEventID.Rendered))
	}
	return jstangle.HTTPRequestFact{
		Kind: "httpRequest", ID: fact.ID + "-handshake", URL: fact.URL,
		Method: jstangle.ValueTemplate{Rendered: "GET", Static: true}, Headers: headers, Client: "protocol",
		Provenance: jstangle.Provenance{Extractor: "eventsource-handshake", Confidence: "high", Start: fact.Provenance.Start, Evidence: fact.Provenance.Evidence},
	}, true
}

func graphQLOperationRequest(operation *jstangle.GraphQLOperationFact) (jstangle.HTTPRequestFact, bool) {
	if operation == nil || operation.Endpoint == nil || operation.Endpoint.Rendered == "" || operation.Transport != "http" {
		return jstangle.HTTPRequestFact{}, false
	}
	payload := make(map[string]any, 3)
	if operation.Document != "" {
		payload["query"] = operation.Document
	}
	if operation.OperationName != "" {
		payload["operationName"] = operation.OperationName
	}
	variables := make(map[string]string, len(operation.Variables))
	templateVariables := make([]jstangle.TemplateVariable, 0, len(operation.Variables))
	for _, variable := range operation.Variables {
		value := "${" + variable.Name + "}"
		if variable.Value != nil && variable.Value.Rendered != "" {
			value = variable.Value.Rendered
		}
		variables[variable.Name] = value
		templateVariables = append(templateVariables, jstangle.TemplateVariable{Name: variable.Name, Placeholder: "${" + variable.Name + "}"})
	}
	if len(variables) > 0 {
		payload["variables"] = variables
	}
	if operation.PersistedQueryHash != "" {
		payload["extensions"] = map[string]any{"persistedQuery": map[string]any{
			"version": 1, "sha256Hash": operation.PersistedQueryHash,
		}}
	}
	if len(payload) == 0 {
		return jstangle.HTTPRequestFact{}, false
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return jstangle.HTTPRequestFact{}, false
	}
	provenance := operation.Provenance
	if provenance.Extractor == "" {
		provenance.Extractor = "graphql-operation"
	}
	if provenance.Confidence == "" {
		provenance.Confidence = "medium"
	}
	return jstangle.HTTPRequestFact{
		Kind: "httpRequest", ID: operation.ID + "-http", URL: *operation.Endpoint,
		Method: jstangle.ValueTemplate{Rendered: "POST", Static: true},
		Headers: []jstangle.HeaderTemplate{{
			Name:  jstangle.ValueTemplate{Rendered: "Content-Type", Static: true},
			Value: jstangle.ValueTemplate{Rendered: "application/json", Static: true},
		}},
		Body: &jstangle.BodyTemplate{
			Kind: "json", ContentType: "application/json",
			Value: jstangle.ValueTemplate{Rendered: string(body), Static: len(templateVariables) == 0, Variables: templateVariables},
		},
		Client: "graphql", OperationType: operation.OperationType, Provenance: provenance,
	}, true
}
