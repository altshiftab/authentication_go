package access_token_parser_config

import (
	"slices"
	"testing"
)

func TestNew(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		options []Option
		want    []string
		wantNil bool
	}{
		{name: "no option", wantNil: true},
		{name: "one subject", options: []Option{WithAllowedSubjects("a")}, want: []string{"a"}},
		{name: "two subjects", options: []Option{WithAllowedSubjects("a", "b")}, want: []string{"a", "b"}},
		{name: "the option without subjects", options: []Option{WithAllowedSubjects()}, want: []string{}},
		{name: "the last option wins", options: []Option{WithAllowedSubjects("a"), WithAllowedSubjects("b")}, want: []string{"b"}},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			config := New(testCase.options...)
			if testCase.wantNil {
				if config.AllowedSubjects != nil {
					t.Errorf("%s: allowed subjects %v, want nil", testCase.name, config.AllowedSubjects)
				}
				return
			}
			if config.AllowedSubjects == nil || !slices.Equal(config.AllowedSubjects, testCase.want) {
				t.Errorf("%s: allowed subjects %v, want %v", testCase.name, config.AllowedSubjects, testCase.want)
			}
		})
	}
}

// The option copies its arguments, so that a caller's slice changed later does not change who is let in.
func TestWithAllowedSubjects_Copies(t *testing.T) {
	t.Parallel()

	subjects := []string{"a"}
	config := New(WithAllowedSubjects(subjects...))
	subjects[0] = "b"
	if !slices.Equal(config.AllowedSubjects, []string{"a"}) {
		t.Errorf("allowed subjects %v, want [a]", config.AllowedSubjects)
	}
}
