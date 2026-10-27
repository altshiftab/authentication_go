package testing

import (
	"encoding/base64"
	"testing"
)

func TestFindAddress(t *testing.T) {
	t.Parallel()

	const address = "person@example.com"

	token := func(payload string) string {
		return "eyJhbGciOiJSUzI1NiJ9." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".(MASKED)"
	}

	testCases := []struct {
		name      string
		written   string
		wantFound int
	}{
		{name: "nowhere", written: `{"user":{"hash":"abc"}}`},
		{name: "as written", written: `{"user":{"email":"` + address + `"}}`, wantFound: 1},
		{name: "in a token", written: "Authorization: Bearer " + token(`{"email":"`+address+`"}`), wantFound: 1},
		{name: "in a token without it", written: "Authorization: Bearer " + token(`{"sub":"(MASKED)"}`)},
		{name: "in two tokens", written: token(`{"email":"`+address+`"}`) + " " + token(`{"e":"`+address+`"}`), wantFound: 2},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if found := FindAddress(testCase.written, address); len(found) != testCase.wantFound {
				t.Errorf("%s: found %q, want %d places", testCase.name, found, testCase.wantFound)
			}
		})
	}
}
