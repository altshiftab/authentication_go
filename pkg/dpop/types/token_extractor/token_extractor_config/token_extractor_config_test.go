package token_extractor_config

import "testing"

func TestNew(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		options []Option
		want    *Config
	}{
		{name: "defaults", want: &Config{AcceptBearer: true}},
		{name: "bearer refused", options: []Option{WithAcceptBearer(false)}, want: &Config{AcceptBearer: false}},
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
