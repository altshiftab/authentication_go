package dpop

import "testing"

func TestChallenge(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name             string
		errorCode        string
		errorDescription string
		want             string
	}{
		{name: "no credential", want: `DPoP algs="ES256"`},
		{name: "description without code is dropped", errorDescription: "ignored", want: `DPoP algs="ES256"`},
		{
			name:      "code only",
			errorCode: ErrorInvalidDpopProof,
			want:      `DPoP error="invalid_dpop_proof", algs="ES256"`,
		},
		{
			name:             "code and description",
			errorCode:        ErrorInvalidToken,
			errorDescription: "The token is not bound to a key.",
			want:             `DPoP error="invalid_token", error_description="The token is not bound to a key.", algs="ES256"`,
		},
		{
			name:             "characters RFC 6750 does not allow are dropped",
			errorCode:        ErrorInvalidDpopProof,
			errorDescription: "a \"quoted\" \\ välue\n",
			want:             `DPoP error="invalid_dpop_proof", error_description="a quoted  vlue", algs="ES256"`,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := Challenge(testCase.errorCode, testCase.errorDescription); got != testCase.want {
				t.Errorf("%s: got %q, want %q", testCase.name, got, testCase.want)
			}
		})
	}
}

func TestBearerChallenge(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name             string
		errorCode        string
		errorDescription string
		want             string
	}{
		{name: "no credential", want: "Bearer"},
		{
			name:             "an RFC 6750 code is carried",
			errorCode:        ErrorInvalidToken,
			errorDescription: "Invalid token.",
			want:             `Bearer error="invalid_token", error_description="Invalid token."`,
		},
		{
			// A bearer client has no proof to fix, so it is told nothing about one.
			name:             "a DPoP code is not",
			errorCode:        ErrorInvalidDpopProof,
			errorDescription: "The DPoP proof is not valid.",
			want:             "Bearer",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := BearerChallenge(testCase.errorCode, testCase.errorDescription); got != testCase.want {
				t.Errorf("%s: got %q, want %q", testCase.name, got, testCase.want)
			}
		})
	}
}

func TestAccessTokenHash(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		accessToken string
		want        string
	}{
		{ //nolint:gosec // The RFC's example token, not a credential.
			// The access token and "ath" of the protected resource request in RFC 9449 §7.1.
			name:        "the RFC's example",
			accessToken: "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU",
			want:        "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo",
		},
		{
			name: "the empty string",
			want: "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := AccessTokenHash(testCase.accessToken); got != testCase.want {
				t.Errorf("%s: got %q, want %q", testCase.name, got, testCase.want)
			}
		})
	}
}
