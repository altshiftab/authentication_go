package authorizer_request_parser_config

import (
	"slices"
	"testing"

	"github.com/Motmedel/utils_go/pkg/http/mux/types/request_parser/token_header_extractor"
)

func TestNew(t *testing.T) {
	t.Parallel()

	config := New()
	if config == nil {
		t.Fatalf("nil config")
	}

	if config.SkipExp {
		t.Errorf("expected skip exp to default to false")
	}
	if config.TokenExtractor != DefaultTokenExtractor {
		t.Errorf("token extractor: got %v", config.TokenExtractor)
	}
	if config.AllowedRoles != nil || config.AllowedTenantId != "" || config.SuperAdminRoles != nil {
		t.Errorf("expected zero role config, got %+v", config)
	}
}

func TestOptions(t *testing.T) {
	t.Parallel()

	tokenExtractor := token_header_extractor.New()

	testCases := []struct {
		name   string
		option Option
		check  func(t *testing.T, config *Config)
	}{
		{
			name:   "with skip exp",
			option: WithSkipExp(true),
			check: func(t *testing.T, config *Config) {
				if !config.SkipExp {
					t.Errorf("expected skip exp")
				}
			},
		},
		{
			name:   "with token extractor",
			option: WithTokenExtractor(tokenExtractor),
			check: func(t *testing.T, config *Config) {
				if config.TokenExtractor != tokenExtractor {
					t.Errorf("token extractor: got %v", config.TokenExtractor)
				}
			},
		},
		{
			name:   "with allowed roles",
			option: WithAllowedRoles("admin", "user"),
			check: func(t *testing.T, config *Config) {
				if !slices.Equal(config.AllowedRoles, []string{"admin", "user"}) {
					t.Errorf("allowed roles: got %v", config.AllowedRoles)
				}
			},
		},
		{
			name:   "with allowed tenant id",
			option: WithAllowedTenantId("tenant-id"),
			check: func(t *testing.T, config *Config) {
				if config.AllowedTenantId != "tenant-id" {
					t.Errorf("allowed tenant id: got %q", config.AllowedTenantId)
				}
			},
		},
		{
			name:   "with super admin roles",
			option: WithSuperAdminRoles("super-admin"),
			check: func(t *testing.T, config *Config) {
				if !slices.Equal(config.SuperAdminRoles, []string{"super-admin"}) {
					t.Errorf("super admin roles: got %v", config.SuperAdminRoles)
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
