package mint_token_config

import "testing"

func TestNew(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		options []Option
		want    *Config
	}{
		{name: "defaults", want: &Config{}},
		{
			name:    "a key thumbprint",
			options: []Option{WithKeyThumbprint("thumbprint")},
			want:    &Config{KeyThumbprint: "thumbprint"},
		},
		{
			name:    "an audience",
			options: []Option{WithAudience("https://vocab.example.com")},
			want:    &Config{Audience: "https://vocab.example.com"},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := New(testCase.options...); *got != *testCase.want {
				t.Errorf("%s: got %+v, want %+v", testCase.name, got, testCase.want)
			}
		})
	}
}
