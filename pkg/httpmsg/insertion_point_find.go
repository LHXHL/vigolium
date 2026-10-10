package httpmsg

import "strings"

// FindInsertionPoint returns the insertion point in ips with the given type
// name and point name, or nil. typeName is an InsertionPointType.String() value
// (URL_PARAM, BODY_PARAM, HEADER, ...) matched case-insensitively; an empty
// typeName matches any type, taking the first point with that name. Header
// names compare case-insensitively, every other name exactly.
//
// It is the one "TYPE:name" lookup shared by `fuzz --point` and `finding
// verify`, which reconstructs the point a stored finding was found on.
func FindInsertionPoint(ips []InsertionPoint, typeName, name string) InsertionPoint {
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		if typeName != "" && !strings.EqualFold(ip.Type().String(), typeName) {
			continue
		}
		if ip.Name() == name || (ip.Type() == INS_HEADER && strings.EqualFold(ip.Name(), name)) {
			return ip
		}
	}
	return nil
}
