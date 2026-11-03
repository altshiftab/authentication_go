package assertion

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"

	"github.com/altshiftab/authentication_go/pkg/api_key/public_key"
	altshiftCryptoEcdsa "github.com/altshiftab/utils_go/pkg/crypto/ecdsa"
	altshiftCryptoEddsa "github.com/altshiftab/utils_go/pkg/crypto/eddsa"
	altshiftCryptoInterfaces "github.com/altshiftab/utils_go/pkg/crypto/interfaces"
	altshiftJwtToken "github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/token"
)

const audience = "https://login.example.test"

/*
 * The moment the test reasons from, taken from the clock rather than written down.
 *
 * A fixed timestamp would make the tests read better and pass only for the minute it named: the
 * claims validator inside authenticated_token compares "exp" against the wall clock, whatever
 * Verify is told the time is, so an assertion built to expire a minute after a date in the source
 * is an expired assertion as soon as that minute has gone by. Every case below is relative to this,
 * which is also how a client builds one.
 */
var now = time.Now()

type signingKey struct {
	key    *public_key.Key
	signer altshiftCryptoInterfaces.NamedSigner
}

func newEddsaSigningKey(t *testing.T) *signingKey {
	t.Helper()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 generate key: %v", err)
	}

	return &signingKey{
		key:    parsePublicKey(t, publicKey),
		signer: &altshiftCryptoEddsa.Method{PrivateKey: privateKey, PublicKey: publicKey},
	}
}

func newEcdsaSigningKey(t *testing.T) *signingKey {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa generate key: %v", err)
	}

	method, err := altshiftCryptoEcdsa.FromPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("ecdsa from private key: %v", err)
	}

	return &signingKey{key: parsePublicKey(t, &privateKey.PublicKey), signer: method}
}

func parsePublicKey(t *testing.T, publicKey any) *public_key.Key {
	t.Helper()

	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("marshal pkix public key: %v", err)
	}

	key, err := public_key.Parse(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})))
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}

	return key
}

// An assertion as a client would build it, with whatever the test wants changed about it.
func makeAssertion(
	t *testing.T,
	key *signingKey,
	header map[string]any,
	payload map[string]any,
) string {
	t.Helper()

	fullHeader := map[string]any{"alg": key.signer.GetName(), "typ": Type}
	fullPayload := map[string]any{
		"iss": key.key.Id,
		"sub": key.key.Id,
		"aud": audience,
		"exp": float64(now.Add(time.Minute).Unix()),
		"iat": float64(now.Unix()),
		"jti": "test-assertion-id",
	}

	for name, value := range header {
		if value == nil {
			delete(fullHeader, name)
			continue
		}
		fullHeader[name] = value
	}
	for name, value := range payload {
		if value == nil {
			delete(fullPayload, name)
			continue
		}
		fullPayload[name] = value
	}

	tokenString, err := (&altshiftJwtToken.Token{Header: fullHeader, Payload: fullPayload}).Encode(key.signer)
	if err != nil {
		t.Fatalf("token encode: %v", err)
	}

	return tokenString
}

/*
 * The same, assembled by hand so that the header says what the test wants it to say.
 *
 * Token.Encode writes the signer's own algorithm into the header, which is right for a client and
 * useless for asking what happens when a header lies: a token built with it can only ever claim the
 * algorithm it was really signed with. An attacker is under no such restraint.
 */
func makeForgedHeaderAssertion(t *testing.T, key *signingKey, header map[string]any) string {
	t.Helper()

	payload := map[string]any{
		"iss": key.key.Id,
		"sub": key.key.Id,
		"aud": audience,
		"exp": float64(now.Add(time.Minute).Unix()),
		"iat": float64(now.Unix()),
		"jti": "test-assertion-id",
	}

	headerBytes, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("json marshal (header): %v", err)
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json marshal (payload): %v", err)
	}

	signingInput := base64.RawURLEncoding.EncodeToString(headerBytes) +
		"." + base64.RawURLEncoding.EncodeToString(payloadBytes)

	signature, err := key.signer.Sign([]byte(signingInput))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

/*
 * What a mint request has to satisfy. Every token here is really signed, and by the key it is
 * verified against but for the one case that says otherwise, so what is under test is the reading
 * of the claims -- which is where an assertion made for one purpose gets used for another.
 */
func TestVerify(t *testing.T) {
	t.Parallel()

	eddsaKey := newEddsaSigningKey(t)
	ecdsaKey := newEcdsaSigningKey(t)
	otherKey := newEddsaSigningKey(t)

	testCases := []struct {
		name    string
		key     *signingKey
		against *public_key.Key
		header  map[string]any
		payload map[string]any
		wantOk  bool
	}{
		{name: "an Ed25519 assertion", key: eddsaKey, wantOk: true},
		{name: "a P-256 assertion", key: ecdsaKey, wantOk: true},
		{
			name:    "one that expires at the edge of the window",
			key:     eddsaKey,
			payload: map[string]any{"exp": float64(now.Add(Lifetime).Unix())},
			wantOk:  true,
		},
		{
			// Clocks on build runners are not exact, and a minute of slack is not a forgery.
			name:    "one issued a moment in the future",
			key:     eddsaKey,
			payload: map[string]any{"iat": float64(now.Add(30 * time.Second).Unix())},
			wantOk:  true,
		},
		{
			// The same slack the other way. A runner whose clock is behind writes an expiry that
			// has already passed by the time it arrives, and is not thereby a replay.
			name:    "one that expired a moment ago",
			key:     eddsaKey,
			payload: map[string]any{"exp": float64(now.Add(-30 * time.Second).Unix())},
			wantOk:  true,
		},
		{
			name:    "one carrying no iat at all",
			key:     eddsaKey,
			payload: map[string]any{"iat": nil},
			wantOk:  true,
		},
		{
			// "sub" is required and compares against the same id, so this is settled without it.
			name:    "one carrying no iss at all",
			key:     eddsaKey,
			payload: map[string]any{"iss": nil},
			wantOk:  true,
		},
		{
			// Giving up the binding to this deployment is the key holder's to give up, and theirs
			// alone: the claim is inside what was signed, so a copy cannot be stripped of it.
			name:    "made for no audience",
			key:     eddsaKey,
			payload: map[string]any{"aud": nil},
			wantOk:  true,
		},
		{
			name:    "one usable since a moment ago",
			key:     eddsaKey,
			payload: map[string]any{"nbf": float64(now.Add(-30 * time.Second).Unix())},
			wantOk:  true,
		},
		// The signature is somebody else's.
		{
			name:    "signed by a key that is not the one claimed",
			key:     otherKey,
			against: eddsaKey.key,
			payload: map[string]any{"iss": eddsaKey.key.Id, "sub": eddsaKey.key.Id},
		},

		// Made for another service, or for another endpoint of this one.
		{
			name:    "made for another audience",
			key:     eddsaKey,
			payload: map[string]any{"aud": "https://login.other.test"},
		},
		// Made for one key and presented under the lookup of another.
		{
			name:    "whose issuer is another key",
			key:     eddsaKey,
			payload: map[string]any{"iss": otherKey.key.Id},
		},
		{
			name:    "whose subject is another key",
			key:     eddsaKey,
			payload: map[string]any{"sub": otherKey.key.Id},
		},
		// Expiry, in both directions: one that has passed, and one so far out that a copy of the
		// assertion would stay useful for a day.
		{
			name:    "that has expired",
			key:     eddsaKey,
			payload: map[string]any{"exp": float64(now.Add(-2 * time.Minute).Unix())},
		},
		{
			name:    "that expires a day from now",
			key:     eddsaKey,
			payload: map[string]any{"exp": float64(now.Add(24 * time.Hour).Unix())},
		},
		{
			name:    "carrying no expiry",
			key:     eddsaKey,
			payload: map[string]any{"exp": nil},
		},
		{
			name:    "issued far in the future",
			key:     eddsaKey,
			payload: map[string]any{"iat": float64(now.Add(10 * time.Minute).Unix())},
		},
		// A client need not say when its assertion becomes usable, but having said it, it is held
		// to it.
		{
			name:    "not usable until later",
			key:     eddsaKey,
			payload: map[string]any{"nbf": float64(now.Add(10 * time.Minute).Unix())},
		},
		// Nothing to remember it by, so nothing to stop it being presented again.
		{
			name:    "carrying no jti",
			key:     eddsaKey,
			payload: map[string]any{"jti": nil},
		},
		{
			name:    "carrying an empty jti",
			key:     eddsaKey,
			payload: map[string]any{"jti": ""},
		},
		{
			name:    "carrying a jti of absurd length",
			key:     eddsaKey,
			payload: map[string]any{"jti": string(make([]byte, 300))},
		},
		// The type is what keeps every other token this service handles out of here.
		{
			name:   "carrying no typ",
			key:    eddsaKey,
			header: map[string]any{"typ": nil},
		},
		{
			name:   "carrying another typ",
			key:    eddsaKey,
			header: map[string]any{"typ": "JWT"},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			against := testCase.against
			if against == nil {
				against = testCase.key.key
			}

			tokenString := makeAssertion(t, testCase.key, testCase.header, testCase.payload)

			gotAssertion, err := Verify(tokenString, against, audience, now)

			if testCase.wantOk {
				if err != nil {
					t.Fatalf("verify: %v", err)
				}
				if gotAssertion == nil {
					t.Fatal("The assertion is nil.")
				}
				if gotAssertion.KeyId != against.Id {
					t.Errorf("key id: got %q, want %q", gotAssertion.KeyId, against.Id)
				}
				if gotAssertion.Jti == "" {
					t.Error("The assertion has no jti to remember it by.")
				}
				return
			}

			if err == nil {
				t.Fatal("The assertion was accepted.")
			}
			if gotAssertion != nil {
				t.Error("An assertion came back alongside the error.")
			}
		})
	}
}

/*
 * A header that lies about the algorithm, which is the classic way into a verifier: the signature is
 * a real one made by the key, and only the name of what made it is wrong. It is refused because the
 * verifier is built from the key that was registered and carries that key's algorithm as its name,
 * so the token is compared against what the key does rather than against what the token asked for.
 */
func TestVerifyRefusesAForgedAlgorithm(t *testing.T) {
	t.Parallel()

	eddsaKey := newEddsaSigningKey(t)
	ecdsaKey := newEcdsaSigningKey(t)

	testCases := []struct {
		name   string
		key    *signingKey
		header map[string]any
	}{
		{
			name:   "an Ed25519 signature claiming ES256",
			key:    eddsaKey,
			header: map[string]any{"alg": "ES256", "typ": Type},
		},
		{
			name:   "a P-256 signature claiming EdDSA",
			key:    ecdsaKey,
			header: map[string]any{"alg": "EdDSA", "typ": Type},
		},
		{
			name:   "one claiming no algorithm at all",
			key:    eddsaKey,
			header: map[string]any{"typ": Type},
		},
		{
			// "none" is the oldest of these: a verifier that reads the header to decide what to do
			// would do nothing at all.
			name:   "one claiming none",
			key:    eddsaKey,
			header: map[string]any{"alg": "none", "typ": Type},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			tokenString := makeForgedHeaderAssertion(t, testCase.key, testCase.header)

			if _, err := Verify(tokenString, testCase.key.key, audience, now); err == nil {
				t.Fatal("The assertion was accepted.")
			}
		})
	}
}

/*
 * The case that says why "typ" is checked at all.
 *
 * A session token is a JWT the service signs with its own key. If somebody registers that public
 * key as their API key -- it is published to every consumer, so anyone can -- then a session token
 * presented to the mint endpoint verifies as a signature made by "their" key. What stops it being
 * read as a mint request is that it says it is a session token and not an assertion.
 */
func TestVerifyRefusesAnotherKindOfToken(t *testing.T) {
	t.Parallel()

	serviceKey := newEddsaSigningKey(t)

	// A session token, as the service mints them: signed by that key, and carrying none of what an
	// assertion carries.
	sessionTokenString, err := (&altshiftJwtToken.Token{
		Header: map[string]any{"alg": serviceKey.signer.GetName(), "typ": "JWT"},
		Payload: map[string]any{
			"iss": "https://login.example.test",
			"sub": "account-id:someone@example.com",
			"aud": []any{"example.test"},
			"exp": float64(now.Add(15 * time.Minute).Unix()),
			"jti": "authentication-id:session-id",
			"amr": []any{"swk"},
		},
	}).Encode(serviceKey.signer)
	if err != nil {
		t.Fatalf("token encode: %v", err)
	}

	if _, err := Verify(sessionTokenString, serviceKey.key, audience, now); err == nil {
		t.Fatal("A session token was accepted as a mint assertion.")
	}
}

func TestSubject(t *testing.T) {
	t.Parallel()

	key := newEddsaSigningKey(t)

	testCases := []struct {
		name        string
		tokenString string
		want        string
		wantErr     bool
	}{
		{
			// Read before anything is verified, which is how the key to verify against is found.
			name:        "an assertion",
			tokenString: makeAssertion(t, key, nil, nil),
			want:        key.key.Id,
		},
		{
			// Unverified: a token signed by nobody still says who it claims to be from, and the
			// signature is checked against the key that name finds.
			name:        "one signed by another key entirely",
			tokenString: makeAssertion(t, newEddsaSigningKey(t), nil, map[string]any{"sub": key.key.Id}),
			want:        key.key.Id,
		},
		{
			name:        "one carrying no subject",
			tokenString: makeAssertion(t, key, nil, map[string]any{"sub": nil}),
			wantErr:     true,
		},
		{name: "nothing at all", tokenString: "", wantErr: true},
		{name: "text that is not a token", tokenString: "not.a.token", wantErr: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got, err := Subject(testCase.tokenString)

			if testCase.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got %q", got)
				}
				return
			}

			if err != nil {
				t.Fatalf("subject: %v", err)
			}
			if got != testCase.want {
				t.Errorf("subject: got %q, want %q", got, testCase.want)
			}
		})
	}
}
