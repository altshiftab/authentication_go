package session

import "testing"

func TestGenerateDbscChallenge(t *testing.T) {
	t.Parallel()

	a, err := GenerateDbscChallenge()
	if err != nil {
		t.Fatalf("GenerateDbscChallenge: %v", err)
	}
	if a == "" {
		t.Fatalf("got empty challenge")
	}

	b, err := GenerateDbscChallenge()
	if err != nil {
		t.Fatalf("GenerateDbscChallenge (2): %v", err)
	}
	if a == b {
		t.Errorf("expected unique challenges, got identical")
	}
}
