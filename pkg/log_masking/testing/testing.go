// Package testing holds what the tests of the endpoints' logging share.
package testing

import (
	"encoding/base64"
	"regexp"
	"strings"
)

// jwsPattern finds a JWS compact serialization in what a log wrote, its signature masked or not.
var jwsPattern = regexp.MustCompile(`eyJ[A-Za-z0-9_-]*\.([A-Za-z0-9_-]+)\.`)

// FindAddress says where an address appears in what a log wrote: as written, and in the payload of
// each token the log wrote out, which base64url hides from a search of the text. Nothing where it
// appears nowhere.
func FindAddress(written string, address string) []string {
	var found []string

	if strings.Contains(written, address) {
		found = append(found, "as written")
	}

	for _, match := range jwsPattern.FindAllStringSubmatch(written, -1) {
		payload, err := base64.RawURLEncoding.DecodeString(match[1])
		if err != nil {
			continue
		}
		if strings.Contains(string(payload), address) {
			found = append(found, "in a token's payload: "+string(payload))
		}
	}

	return found
}
