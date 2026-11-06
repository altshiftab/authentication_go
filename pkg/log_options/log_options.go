// Package log_options is what an endpoint's audit lines say about the person they concern, and what
// the service mounting the endpoint adds to them. It is the one place the endpoints take both from,
// so that a service configures every endpoint it mounts alike.
package log_options

import (
	"log/slog"

	"github.com/altshiftab/utils_go/pkg/log/pii_hasher"
	"github.com/altshiftab/utils_go/pkg/schema"
)

// The ECS vocabulary the endpoints' events are given in: event.category, event.type and
// event.outcome take values from fixed lists, which these name. An authentication is a start (or, a
// revocation, an end) whatever became of it, the outcome saying which -- so that one query over the
// type and the outcome finds every refusal, by whichever route it came.
const (
	CategoryAuthentication = "authentication"
	CategoryIam            = "iam"

	TypeStart    = "start"
	TypeEnd      = "end"
	TypeCreation = "creation"

	OutcomeSuccess = "success"
	OutcomeFailure = "failure"
	OutcomeUnknown = "unknown"
)

type Config struct {
	// EmailAddressHasher names a person's address by its keyed hash, which matches across entries
	// and can be looked up by hashing an address someone gives. With none, no hash is written.
	EmailAddressHasher *pii_hasher.Hasher

	// LogEmailAddress writes the address itself beside the id and the hash. Off by default: the id
	// names an account to whoever can look it up, and the hash an address to whoever has it.
	LogEmailAddress bool

	// EventAttrs are added inside the event group of every audit line, after the endpoint's own
	// fields: a service's dataset, for one, which its log router tells the audit trail by. They are
	// given to the endpoint rather than passed as an event group of LogAttrs because whether two
	// groups of one name are merged is the handler's to decide: utils_go's context logger merges
	// them, slog's own JSON handler writes the key twice, and the library cannot know which a
	// service logs through.
	EventAttrs []slog.Attr

	// LogAttrs are added at the top level of every audit line.
	LogAttrs []slog.Attr
}

type Option func(*Config)

func New(options ...Option) *Config {
	config := &Config{}
	for _, option := range options {
		if option != nil {
			option(config)
		}
	}

	return config
}

func WithEmailAddressHasher(emailAddressHasher *pii_hasher.Hasher) Option {
	return func(config *Config) {
		config.EmailAddressHasher = emailAddressHasher
	}
}

func WithLogEmailAddress(logEmailAddress bool) Option {
	return func(config *Config) {
		config.LogEmailAddress = logEmailAddress
	}
}

// WithEventAttrs adds to the event group of every audit line. They should not repeat the endpoint's
// own fields -- category, type, action, outcome and reason: a handler that merges groups lets the
// later value replace the endpoint's, and one that does not writes the key twice.
func WithEventAttrs(eventAttrs ...slog.Attr) Option {
	return func(config *Config) {
		config.EventAttrs = append(config.EventAttrs, eventAttrs...)
	}
}

func WithLogAttrs(logAttrs ...slog.Attr) Option {
	return func(config *Config) {
		config.LogAttrs = append(config.LogAttrs, logAttrs...)
	}
}

// Apply sets options on a config that exists already, as on an endpoint's Log once it is made: a
// service that makes its endpoints in one place and has its hasher in another adds the hasher without
// replacing what was set before. Unlike New, it keeps what it is not given.
func (c *Config) Apply(options ...Option) {
	if c == nil {
		return
	}
	for _, option := range options {
		if option != nil {
			option(c)
		}
	}
}

// EmailAddressHash is the keyed hash of emailAddress, or empty without a hasher or an address.
func (c *Config) EmailAddressHash(emailAddress string) string {
	if c == nil {
		return ""
	}

	return c.EmailAddressHasher.HashEmailAddress(emailAddress)
}

// UserAttrs names the person an audit line concerns, as the attributes of its user group: the id
// when there is one, the address's keyed hash with a hasher, and the address itself only when
// LogEmailAddress is set.
func (c *Config) UserAttrs(id string, emailAddress string) []any {
	var attrs []any
	if id != "" {
		attrs = append(attrs, slog.String("id", id))
	}
	if hash := c.EmailAddressHash(emailAddress); hash != "" {
		attrs = append(attrs, slog.String("hash", hash))
	}
	if c != nil && c.LogEmailAddress && emailAddress != "" {
		attrs = append(attrs, slog.String("email", emailAddress))
	}

	return attrs
}

// User names the same person for the request log, which takes its user from the HTTP context.
func (c *Config) User(id string, emailAddress string) *schema.User {
	user := &schema.User{Id: id, Hash: c.EmailAddressHash(emailAddress)}
	if c != nil && c.LogEmailAddress {
		user.Email = emailAddress
	}

	return user
}

// Event is the event group of an audit line: the ECS categories, types, action and outcome the
// endpoint gives it, the reason when there is one, and then the EventAttrs.
func (c *Config) Event(categories []string, types []string, action string, outcome string, reason string) slog.Attr {
	attrs := []any{
		slog.Any("category", categories),
		slog.Any("type", types),
		slog.String("action", action),
		slog.String("outcome", outcome),
	}
	if reason != "" {
		attrs = append(attrs, slog.String("reason", reason))
	}
	if c != nil {
		for _, eventAttr := range c.EventAttrs {
			attrs = append(attrs, eventAttr)
		}
	}

	return slog.Group("event", attrs...)
}

// Attrs is the attributes of an audit line with the LogAttrs after them.
func (c *Config) Attrs(attrs ...any) []any {
	if c == nil || len(c.LogAttrs) == 0 {
		return attrs
	}

	lineAttrs := make([]any, 0, len(attrs)+len(c.LogAttrs))
	lineAttrs = append(lineAttrs, attrs...)
	for _, logAttr := range c.LogAttrs {
		lineAttrs = append(lineAttrs, logAttr)
	}

	return lineAttrs
}
