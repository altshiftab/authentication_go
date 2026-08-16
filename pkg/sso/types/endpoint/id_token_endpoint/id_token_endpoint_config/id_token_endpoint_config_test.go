package id_token_endpoint_config

import "testing"

func TestNew(t *testing.T) {
	t.Parallel()

	if config := New(); config == nil {
		t.Fatalf("nil config")
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
