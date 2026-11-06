package log_options

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"reflect"
	"testing"

	"github.com/altshiftab/utils_go/pkg/log/pii_hasher"
)

func newHasher(t *testing.T) *pii_hasher.Hasher {
	t.Helper()

	hasher, err := pii_hasher.New(bytes.Repeat([]byte{7}, pii_hasher.MinimumKeyLength))
	if err != nil {
		t.Fatalf("pii hasher new: %v", err)
	}

	return hasher
}

// render writes one line with attrs and returns it as decoded JSON.
func render(t *testing.T, attrs ...any) map[string]any {
	t.Helper()

	var buffer bytes.Buffer
	slog.New(slog.NewJSONHandler(&buffer, nil)).Info("line", attrs...)

	var record map[string]any
	if err := json.Unmarshal(buffer.Bytes(), &record); err != nil {
		t.Fatalf("json unmarshal: %v", err)
	}

	return record
}

func TestUserAttrs(t *testing.T) {
	t.Parallel()

	hasher := newHasher(t)
	const emailAddress = "alice@example.com"

	testCases := []struct {
		name         string
		config       *Config
		id           string
		emailAddress string
		want         map[string]any
	}{
		{
			name:         "without options the address is not written at all",
			config:       New(),
			id:           "account-id",
			emailAddress: emailAddress,
			want:         map[string]any{"id": "account-id"},
		},
		{
			name:         "a nil config writes the id alone",
			id:           "account-id",
			emailAddress: emailAddress,
			want:         map[string]any{"id": "account-id"},
		},
		{
			name:         "with a hasher the address is named by its hash",
			config:       New(WithEmailAddressHasher(hasher)),
			id:           "account-id",
			emailAddress: emailAddress,
			want:         map[string]any{"id": "account-id", "hash": hasher.HashEmailAddress(emailAddress)},
		},
		{
			name:         "the address itself only when asked for",
			config:       New(WithEmailAddressHasher(hasher), WithLogEmailAddress(true)),
			id:           "account-id",
			emailAddress: emailAddress,
			want: map[string]any{
				"id":    "account-id",
				"hash":  hasher.HashEmailAddress(emailAddress),
				"email": emailAddress,
			},
		},
		{
			name:         "no id and no address name nobody",
			config:       New(WithEmailAddressHasher(hasher), WithLogEmailAddress(true)),
			emailAddress: "",
			want:         nil,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			record := render(t, slog.Group("user", testCase.config.UserAttrs(testCase.id, testCase.emailAddress)...))
			got, _ := record["user"].(map[string]any)
			if len(got) == 0 && len(testCase.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, testCase.want) {
				t.Errorf("got user %v, want %v", got, testCase.want)
			}

			user := testCase.config.User(testCase.id, testCase.emailAddress)
			if user.Id != testCase.id || user.Hash != stringOf(testCase.want["hash"]) || user.Email != stringOf(testCase.want["email"]) {
				t.Errorf("got the request log's user %+v, want the line's %v", user, testCase.want)
			}
		})
	}
}

func stringOf(value any) string {
	s, _ := value.(string)
	return s
}

func TestEventAndAttrs(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		config    *Config
		reason    string
		wantEvent map[string]any
		wantExtra map[string]any
	}{
		{
			name:   "the endpoint's own fields alone",
			config: New(),
			wantEvent: map[string]any{
				"category": []any{"authentication"},
				"type":     []any{"start"},
				"action":   "sign_in",
				"outcome":  "success",
			},
		},
		{
			name:   "a reason, the service's event attributes inside the group, and its line attributes beside it",
			config: New(WithEventAttrs(slog.String("dataset", "service.audit")), WithLogAttrs(slog.String("environment", "test"))),
			reason: "A user signed in.",
			wantEvent: map[string]any{
				"category": []any{"authentication"},
				"type":     []any{"start"},
				"action":   "sign_in",
				"outcome":  "success",
				"reason":   "A user signed in.",
				"dataset":  "service.audit",
			},
			wantExtra: map[string]any{"environment": "test"},
		},
		{
			name: "a nil config adds nothing",
			wantEvent: map[string]any{
				"category": []any{"authentication"},
				"type":     []any{"start"},
				"action":   "sign_in",
				"outcome":  "success",
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			record := render(
				t,
				testCase.config.Attrs(
					testCase.config.Event([]string{"authentication"}, []string{"start"}, "sign_in", "success", testCase.reason),
				)...,
			)

			if got := record["event"]; !reflect.DeepEqual(got, testCase.wantEvent) {
				t.Errorf("got event %v, want %v", got, testCase.wantEvent)
			}
			for key, want := range testCase.wantExtra {
				if got := record[key]; got != want {
					t.Errorf("got %s %v, want %v", key, got, want)
				}
			}
		})
	}
}

func TestApply(t *testing.T) {
	t.Parallel()

	hasher := newHasher(t)

	testCases := []struct {
		name          string
		config        *Config
		options       []Option
		wantHasher    bool
		wantEventAttr bool
	}{
		{
			name:          "an option added keeps what was set before",
			config:        New(WithEventAttrs(slog.String("dataset", "service.audit"))),
			options:       []Option{WithEmailAddressHasher(hasher)},
			wantHasher:    true,
			wantEventAttr: true,
		},
		{
			name:    "a nil config is left alone",
			options: []Option{WithEmailAddressHasher(hasher)},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			testCase.config.Apply(testCase.options...)
			if testCase.config == nil {
				return
			}
			if got := testCase.config.EmailAddressHasher != nil; got != testCase.wantHasher {
				t.Errorf("hasher set: %t, want %t", got, testCase.wantHasher)
			}
			if got := len(testCase.config.EventAttrs) == 1; got != testCase.wantEventAttr {
				t.Errorf("event attribute kept: %t, want %t", got, testCase.wantEventAttr)
			}
		})
	}
}
