package database

// NotFoundBaseline is how one origin answers a request for a path no
// application serves: the yardstick every later record from that origin is
// compared against, so "this path exists" stops being a question answered by
// diffing bodies by hand.
//
// A host that answers 200 to a random path (SoftNotFound) is a fact worth
// knowing on its own — every discovery result from it needs this comparison to
// mean anything — and is stored as a fact, not a finding.
type NotFoundBaseline struct {
	// Paths are the random paths requested.
	Paths []string `json:"paths"`
	// Status, Length, Words, Lines, ContentType, Title and Location describe the
	// first answer.
	Status      int    `json:"status"`
	Length      int    `json:"length"`
	Words       int    `json:"words"`
	Lines       int    `json:"lines"`
	ContentType string `json:"content_type,omitempty"`
	Title       string `json:"title,omitempty"`
	Location    string `json:"location,omitempty"`
	// SoftNotFound reports a 2xx/3xx answer to a missing path.
	SoftNotFound bool `json:"soft_not_found"`
	// Signature is the response-attribute hashes stable across every answer
	// (deparos/fingerprint), keyed by attribute name. A record whose response
	// matches every one of them is the not-found page, whatever its status.
	Signature map[string]uint32 `json:"signature,omitempty"`
}
