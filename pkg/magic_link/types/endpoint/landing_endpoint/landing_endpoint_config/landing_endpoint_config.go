package landing_endpoint_config

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"html/template"

	motmedelHttpTypes "github.com/Motmedel/utils_go/pkg/http/types"
	cspParsing "github.com/Motmedel/utils_go/pkg/http/types/content_security_policy"
	cspUtils "github.com/Motmedel/utils_go/pkg/http/utils/content_security_policy"
)

type PageBuilder func(formAction string, acceptLanguage *motmedelHttpTypes.AcceptLanguage) ([]byte, error)

const defaultInlineStyle = `body{font-family:system-ui,sans-serif;display:flex;min-height:100vh;margin:0;align-items:center;justify-content:center;background:#f5f5f5;color:#111}.card{background:#fff;padding:2rem;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.1);text-align:center;max-width:24rem;width:100%;box-sizing:border-box}h1{margin:0 0 .5rem;font-size:1.25rem}p{margin:0 0 1.5rem;color:#555}button{padding:.75rem 1.5rem;font-size:1rem;border:0;border-radius:4px;background:#111;color:#fff;cursor:pointer}button:hover{background:#333}`

var (
	DefaultPath = "/api/login/magic/validate"

	// DefaultStyleSrcHash is the CSP source value (algorithm-prefixed) for the inline <style> block emitted by
	// DefaultPageBuilder. Exposed so consumers can wire it into their own CSP setup if they bypass
	// DefaultContentSecurityPolicy.
	DefaultStyleSrcHash = computeCspSha256(defaultInlineStyle)

	// DefaultContentSecurityPolicy is a strict CSP that allows the inline <style> block via its hash and permits the
	// POST form submission to 'self'. It is emitted by the handler as Content-Security-Policy with Overwrite=true,
	// so it replaces the mux's default CSP only for this endpoint.
	DefaultContentSecurityPolicy = buildDefaultCsp()

	defaultPageTemplate = template.Must(template.New("landing").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Sign in</title>
<style>` + defaultInlineStyle + `</style>
</head>
<body>
<main class="card">
<h1>Sign in</h1>
<p>Click the button below to complete your sign-in.</p>
<form method="POST" action="{{.Action}}"><button type="submit">Sign in</button></form>
</main>
</body>
</html>
`))

	DefaultPageBuilder PageBuilder = func(formAction string, _ *motmedelHttpTypes.AcceptLanguage) ([]byte, error) {
		var buf bytes.Buffer
		if err := defaultPageTemplate.Execute(&buf, struct{ Action string }{Action: formAction}); err != nil {
			return nil, fmt.Errorf("template execute: %w", err)
		}
		return buf.Bytes(), nil
	}
)

func computeCspSha256(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
}

func buildDefaultCsp() string {
	const baseCsp = "default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'"
	parsed, err := cspParsing.Parse([]byte(baseCsp))
	if err != nil {
		panic(fmt.Errorf("landing_endpoint_config: parse base csp: %w", err))
	}
	if err := cspUtils.PatchCspStyleSrcWithHash(parsed, DefaultStyleSrcHash); err != nil {
		panic(fmt.Errorf("landing_endpoint_config: patch style-src with hash: %w", err))
	}
	return parsed.String()
}

type Config struct {
	Path                  string
	PageBuilder           PageBuilder
	ContentSecurityPolicy string
}

type Option func(*Config)

func New(options ...Option) *Config {
	config := &Config{
		Path:                  DefaultPath,
		PageBuilder:           DefaultPageBuilder,
		ContentSecurityPolicy: DefaultContentSecurityPolicy,
	}
	for _, option := range options {
		option(config)
	}
	return config
}

func WithPath(path string) Option {
	return func(config *Config) {
		config.Path = path
	}
}

func WithPageBuilder(pageBuilder PageBuilder) Option {
	return func(config *Config) {
		config.PageBuilder = pageBuilder
	}
}

func WithContentSecurityPolicy(contentSecurityPolicy string) Option {
	return func(config *Config) {
		config.ContentSecurityPolicy = contentSecurityPolicy
	}
}
