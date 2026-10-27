package proof_verifier_config

import (
	"context"
	"testing"
	"time"
)

type fakeReplayDetector struct{}

func (*fakeReplayDetector) Observe(context.Context, string, string, time.Time, time.Time) (bool, error) {
	return false, nil
}

func TestNew(t *testing.T) {
	t.Parallel()

	replayDetector := &fakeReplayDetector{}

	testCases := []struct {
		name    string
		options []Option
		want    *Config
	}{
		{
			name: "defaults",
			want: &Config{
				MaxAge:         DefaultMaxAge,
				ClockSkew:      DefaultClockSkew,
				MaxProofLength: DefaultMaxProofLength,
				MaxIdLength:    DefaultMaxIdLength,
			},
		},
		{
			name: "every option",
			options: []Option{
				WithMaxAge(10 * time.Second),
				WithClockSkew(5 * time.Second),
				WithReplayDetector(replayDetector),
			},
			want: &Config{
				MaxAge:         10 * time.Second,
				ClockSkew:      5 * time.Second,
				MaxProofLength: DefaultMaxProofLength,
				MaxIdLength:    DefaultMaxIdLength,
				ReplayDetector: replayDetector,
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got := New(testCase.options...)
			if *got != *testCase.want {
				t.Errorf("%s: got %+v, want %+v", testCase.name, got, testCase.want)
			}
		})
	}
}
