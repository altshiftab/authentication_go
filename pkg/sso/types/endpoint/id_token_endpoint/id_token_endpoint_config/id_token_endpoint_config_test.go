package id_token_endpoint_config

import "testing"

func TestNew(t *testing.T) {
	t.Parallel()

	if config := New(); config == nil {
		t.Fatalf("nil config")
	}
}

func TestWithRequireOrganization(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		options []Option
		want    bool
	}{
		{
			// A deployment that says nothing keeps admitting an account without an organization.
			name: "default",
			want: DefaultRequireOrganization,
		},
		{
			name:    "required",
			options: []Option{WithRequireOrganization(true)},
			want:    true,
		},
		{
			name:    "explicitly not required",
			options: []Option{WithRequireOrganization(false)},
			want:    false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			config := New(testCase.options...)
			if config.RequireOrganization != testCase.want {
				t.Errorf("%s: RequireOrganization = %v, want %v", testCase.name, config.RequireOrganization, testCase.want)
			}
		})
	}
}

func TestOptions(t *testing.T) {
	t.Parallel()

	invoked := false
	New(func(_ *Config) {
		invoked = true
	})

	if !invoked {
		t.Errorf("expected the option to be invoked")
	}
}
