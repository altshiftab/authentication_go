package validate_endpoint_config

import "testing"

func TestNew_Defaults(t *testing.T) {
	t.Parallel()
	c := New()
	if c.Path != DefaultPath {
		t.Errorf("Path: got %q, want %q", c.Path, DefaultPath)
	}
}

func TestWithPath(t *testing.T) {
	t.Parallel()
	c := New(WithPath("/custom"))
	if c.Path != "/custom" {
		t.Errorf("Path: got %q, want %q", c.Path, "/custom")
	}
}
