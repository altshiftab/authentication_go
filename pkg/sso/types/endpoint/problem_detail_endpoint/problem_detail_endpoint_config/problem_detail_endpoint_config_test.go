package problem_detail_endpoint_config

import (
	"net/http"
	"testing"

	"github.com/Motmedel/utils_go/pkg/http/mux/types/response_error"
)

func TestNew(t *testing.T) {
	t.Parallel()

	config := New()
	if config == nil {
		t.Fatalf("nil config")
	}

	if config.CacheControl != DefaultCacheControl {
		t.Errorf("cache control: got %q", config.CacheControl)
	}
	if config.BackUrl != DefaultBackUrl {
		t.Errorf("back url: got %q", config.BackUrl)
	}
	if config.Path != "" || config.Type != "" || config.Title != "" || config.Detail != "" || config.Status != 0 {
		t.Errorf("expected zero problem fields, got %+v", config)
	}
	if config.Converter != nil {
		t.Errorf("expected nil converter")
	}
}

func TestOptions(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		option Option
		check  func(t *testing.T, config *Config)
	}{
		{
			name:   "with path",
			option: WithPath("/problem"),
			check: func(t *testing.T, config *Config) {
				if config.Path != "/problem" {
					t.Errorf("path: got %q", config.Path)
				}
			},
		},
		{
			name:   "with type",
			option: WithType("https://example.com/problems/failed"),
			check: func(t *testing.T, config *Config) {
				if config.Type != "https://example.com/problems/failed" {
					t.Errorf("type: got %q", config.Type)
				}
			},
		},
		{
			name:   "with title",
			option: WithTitle("Sign-in failed"),
			check: func(t *testing.T, config *Config) {
				if config.Title != "Sign-in failed" {
					t.Errorf("title: got %q", config.Title)
				}
			},
		},
		{
			name:   "with detail",
			option: WithDetail("Something went wrong."),
			check: func(t *testing.T, config *Config) {
				if config.Detail != "Something went wrong." {
					t.Errorf("detail: got %q", config.Detail)
				}
			},
		},
		{
			name:   "with status",
			option: WithStatus(http.StatusForbidden),
			check: func(t *testing.T, config *Config) {
				if config.Status != http.StatusForbidden {
					t.Errorf("status: got %d", config.Status)
				}
			},
		},
		{
			name:   "with cache control",
			option: WithCacheControl("no-store"),
			check: func(t *testing.T, config *Config) {
				if config.CacheControl != "no-store" {
					t.Errorf("cache control: got %q", config.CacheControl)
				}
			},
		},
		{
			name:   "with back url",
			option: WithBackUrl("/login"),
			check: func(t *testing.T, config *Config) {
				if config.BackUrl != "/login" {
					t.Errorf("back url: got %q", config.BackUrl)
				}
			},
		},
		{
			name:   "with back label",
			option: WithBackLabel("Back"),
			check: func(t *testing.T, config *Config) {
				if config.BackLabel != "Back" {
					t.Errorf("back label: got %q", config.BackLabel)
				}
			},
		},
		{
			name:   "with problem detail converter",
			option: WithProblemDetailConverter(response_error.DefaultProblemDetailConverter),
			check: func(t *testing.T, config *Config) {
				if config.Converter == nil {
					t.Errorf("expected converter")
				}
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			testCase.check(t, New(testCase.option))
		})
	}
}
