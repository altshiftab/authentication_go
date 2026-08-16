package session_cookie_config

import (
	"net/http"
	"testing"
)

func TestNew(t *testing.T) {
	t.Parallel()

	config := New(nil)
	if config == nil {
		t.Fatalf("nil config")
	}

	if config.SameSite != DefaultSameSite {
		t.Errorf("same site: got %v", config.SameSite)
	}
}

func TestOptions(t *testing.T) {
	t.Parallel()

	if config := New(WithSameSite(http.SameSiteStrictMode)); config.SameSite != http.SameSiteStrictMode {
		t.Errorf("same site: got %v", config.SameSite)
	}
}
