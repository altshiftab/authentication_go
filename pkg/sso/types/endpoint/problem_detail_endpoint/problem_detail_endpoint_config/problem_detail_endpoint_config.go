package problem_detail_endpoint_config

import (
	"github.com/Motmedel/utils_go/pkg/http/mux/types/response_error"
)

// DefaultCacheControl is applied to served problem documents. They are static
// per type, so they are safe to cache publicly; the response also varies by
// `Accept`, which the response writer emits as a `Vary` header.
const DefaultCacheControl = "public, max-age=3600"

// DefaultBackUrl is the target of the "back to sign in" link on the HTML page.
// Set BackUrl to an empty string to omit the link entirely.
const DefaultBackUrl = "/"

type Config struct {
	Path         string
	Type         string
	Title        string
	Detail       string
	Status       int
	CacheControl string

	// BackUrl is rendered as a "back to sign in" link on the HTML representation
	// served to browsers; it defaults to DefaultBackUrl. Set it to an empty string
	// to omit the link. BackLabel overrides the link text.
	BackUrl   string
	BackLabel string

	// Converter overrides how the problem detail is serialized. When nil, the
	// endpoint defaults to an HTML-capable converter: HTML (with the BackUrl link)
	// for browsers, and problem+json / problem+xml / text/plain otherwise. Pass
	// response_error.DefaultProblemDetailConverter to opt out of HTML entirely.
	Converter response_error.ProblemDetailConverter
}

type Option func(*Config)

func New(options ...Option) *Config {
	config := &Config{
		CacheControl: DefaultCacheControl,
		BackUrl:      DefaultBackUrl,
	}
	for _, option := range options {
		option(config)
	}

	return config
}

// WithPath sets the path the endpoint is mounted at. The named problem
// endpoints (sign_in_cancelled_endpoint, etc.) default this to their canonical
// path, so callers do not normally set it.
func WithPath(path string) Option {
	return func(config *Config) {
		config.Path = path
	}
}

// WithType sets the RFC 9457 problem type URI. It should be a stable,
// preferably dereferenceable identifier for the problem type.
func WithType(problemType string) Option {
	return func(config *Config) {
		config.Type = problemType
	}
}

// WithTitle overrides the problem title. When empty, the HTTP status phrase is
// used (the problem_detail default).
func WithTitle(title string) Option {
	return func(config *Config) {
		config.Title = title
	}
}

func WithDetail(detail string) Option {
	return func(config *Config) {
		config.Detail = detail
	}
}

func WithStatus(status int) Option {
	return func(config *Config) {
		config.Status = status
	}
}

func WithCacheControl(cacheControl string) Option {
	return func(config *Config) {
		config.CacheControl = cacheControl
	}
}

// WithBackUrl sets the target of the "back to sign in" link on the HTML page.
func WithBackUrl(backUrl string) Option {
	return func(config *Config) {
		config.BackUrl = backUrl
	}
}

// WithBackLabel overrides the text of the "back to sign in" link.
func WithBackLabel(label string) Option {
	return func(config *Config) {
		config.BackLabel = label
	}
}

func WithProblemDetailConverter(converter response_error.ProblemDetailConverter) Option {
	return func(config *Config) {
		config.Converter = converter
	}
}
