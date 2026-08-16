package testing

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Motmedel/utils_go/pkg/http/mux/types/request_parser/token_cookie_extractor/token_cookie_extractor_config"
)

func TestSetUp(t *testing.T) {
	t.Parallel()

	authorizerRequestParser, signer, testDb := SetUp()
	if authorizerRequestParser == nil || signer == nil || testDb == nil {
		t.Fatalf("incomplete setup")
	}
	defer testDb.Close()
}

func TestMakeStandardCookie(t *testing.T) {
	t.Parallel()

	_, signer, testDb := SetUp()
	defer testDb.Close()

	cookieString := MakeStandardCookie(AuthenticationId, signer)
	if cookieString == "" {
		t.Fatalf("empty cookie string")
	}

	header := http.Header{}
	header.Add("Set-Cookie", cookieString)
	cookies := (&http.Response{Header: header}).Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookie count: got %d", len(cookies))
	}

	cookie := cookies[0]
	if cookie.Name != token_cookie_extractor_config.DefaultName {
		t.Errorf("cookie name: got %q", cookie.Name)
	}
	if strings.Count(cookie.Value, ".") != 2 {
		t.Errorf("expected a jwt cookie value, got %q", cookie.Value)
	}
}

func TestMakeCookieExplicitPanicsOnNilSigner(t *testing.T) {
	t.Parallel()

	defer func() {
		if recover() == nil {
			t.Errorf("expected panic")
		}
	}()

	MakeCookieExplicit(AuthenticationId, nil, []string{"ext"}, time.Now().Add(time.Hour), time.Now())
}
