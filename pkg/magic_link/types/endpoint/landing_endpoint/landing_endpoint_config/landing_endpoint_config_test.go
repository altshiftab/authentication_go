package landing_endpoint_config

import (
	"strings"
	"testing"

	motmedelHttpTypes "github.com/Motmedel/utils_go/pkg/http/types"
)

func TestNew(t *testing.T) {
	t.Parallel()

	config := New()
	if config == nil {
		t.Fatalf("nil config")
	}

	if config.Path != DefaultPath {
		t.Errorf("path: got %q", config.Path)
	}
	if config.PageBuilder == nil {
		t.Errorf("nil page builder")
	}
	if config.ContentSecurityPolicy != DefaultContentSecurityPolicy {
		t.Errorf("content security policy: got %q", config.ContentSecurityPolicy)
	}
}

func TestDefaultStyleSrcHash(t *testing.T) {
	t.Parallel()

	if !strings.HasPrefix(DefaultStyleSrcHash, "sha256-") {
		t.Errorf("style src hash: got %q", DefaultStyleSrcHash)
	}
}

func TestDefaultContentSecurityPolicy(t *testing.T) {
	t.Parallel()

	if !strings.Contains(DefaultContentSecurityPolicy, "default-src 'self'") {
		t.Errorf("missing default-src: %q", DefaultContentSecurityPolicy)
	}
	if !strings.Contains(DefaultContentSecurityPolicy, DefaultStyleSrcHash) {
		t.Errorf("missing style hash: %q", DefaultContentSecurityPolicy)
	}
}

func TestDefaultPageBuilder(t *testing.T) {
	t.Parallel()

	page, err := DefaultPageBuilder("/api/login/magic/validate?token=abc", nil)
	if err != nil {
		t.Fatalf("default page builder: %v", err)
	}

	body := string(page)
	if !strings.Contains(body, `action="/api/login/magic/validate?token=abc"`) {
		t.Errorf("missing form action:\n%s", body)
	}
	if !strings.Contains(body, `method="POST"`) {
		t.Errorf("missing POST method:\n%s", body)
	}
	if !strings.Contains(body, "<style>") {
		t.Errorf("missing style block:\n%s", body)
	}
}

func TestOptions(t *testing.T) {
	t.Parallel()

	t.Run("with path", func(t *testing.T) {
		t.Parallel()

		if config := New(WithPath("/custom")); config.Path != "/custom" {
			t.Errorf("path: got %q", config.Path)
		}
	})

	t.Run("with page builder", func(t *testing.T) {
		t.Parallel()

		invoked := false
		config := New(WithPageBuilder(func(_ string, _ *motmedelHttpTypes.AcceptLanguage) ([]byte, error) {
			invoked = true
			return nil, nil
		}))

		if _, err := config.PageBuilder("", nil); err != nil {
			t.Fatalf("page builder: %v", err)
		}
		if !invoked {
			t.Errorf("expected the configured page builder to be invoked")
		}
	})

	t.Run("with content security policy", func(t *testing.T) {
		t.Parallel()

		if config := New(WithContentSecurityPolicy("default-src 'none'")); config.ContentSecurityPolicy != "default-src 'none'" {
			t.Errorf("content security policy: got %q", config.ContentSecurityPolicy)
		}
	})
}
