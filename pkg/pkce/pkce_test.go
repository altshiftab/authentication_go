package pkce

import (
	"strings"
	"testing"
)

// The verifier and challenge of RFC 7636 Appendix B.
const (
	rfcVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	rfcChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

func TestChallengeS256(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		verifier string
		want     string
	}{
		{name: "the RFC's example", verifier: rfcVerifier, want: rfcChallenge},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := ChallengeS256(testCase.verifier); got != testCase.want {
				t.Errorf("%s: got %q, want %q", testCase.name, got, testCase.want)
			}
		})
	}
}

func TestMatchesS256(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		verifier  string
		challenge string
		want      bool
	}{
		{name: "the RFC's example", verifier: rfcVerifier, challenge: rfcChallenge, want: true},
		{name: "another verifier", verifier: strings.Repeat("a", 43), challenge: rfcChallenge},
		{
			// "plain": the challenge is the verifier itself, which S256 never accepts.
			name:      "the verifier as its own challenge",
			verifier:  rfcVerifier,
			challenge: rfcVerifier,
		},
		{
			// A verifier too short to be unguessable does not match even the hash of itself.
			name:      "a short verifier",
			verifier:  "short",
			challenge: ChallengeS256("short"),
		},
		{name: "no verifier", challenge: rfcChallenge},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := MatchesS256(testCase.verifier, testCase.challenge); got != testCase.want {
				t.Errorf("%s: got %v, want %v", testCase.name, got, testCase.want)
			}
		})
	}
}

func TestValidVerifier(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		verifier string
		want     bool
	}{
		{name: "the RFC's example", verifier: rfcVerifier, want: true},
		{name: "the shortest", verifier: strings.Repeat("a", 43), want: true},
		{name: "the longest", verifier: strings.Repeat("a", 128), want: true},
		{name: "every unreserved character", verifier: "AZaz09-._~" + strings.Repeat("a", 33), want: true},
		{name: "one short", verifier: strings.Repeat("a", 42)},
		{name: "one long", verifier: strings.Repeat("a", 129)},
		{name: "a reserved character", verifier: strings.Repeat("a", 42) + "/"},
		{name: "a space", verifier: strings.Repeat("a", 42) + " "},
		{name: "a non-ASCII character", verifier: strings.Repeat("a", 41) + "é"},
		{name: "empty"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := ValidVerifier(testCase.verifier); got != testCase.want {
				t.Errorf("%s: got %v, want %v", testCase.name, got, testCase.want)
			}
		})
	}
}

func TestValidChallenge(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		challenge string
		want      bool
	}{
		{name: "the RFC's example", challenge: rfcChallenge, want: true},
		{name: "one short", challenge: rfcChallenge[:42]},
		{name: "padded", challenge: rfcChallenge + "="},
		{name: "the standard alphabet", challenge: strings.ReplaceAll(rfcChallenge, "-", "+")},
		{name: "empty"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := ValidChallenge(testCase.challenge); got != testCase.want {
				t.Errorf("%s: got %v, want %v", testCase.name, got, testCase.want)
			}
		})
	}
}
