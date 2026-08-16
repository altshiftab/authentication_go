package endpoint

import "testing"

func TestNew(t *testing.T) {
	t.Parallel()

	overview := New()
	if overview == nil {
		t.Fatalf("nil overview")
	}

	if overview.RefreshEndpoint == nil || overview.EndEndpoint == nil ||
		overview.DbscRefreshEndpoint == nil || overview.DbscRegisterEndpoint == nil {
		t.Fatalf("expected all endpoints, got %+v", overview)
	}
}

func TestEndpoints(t *testing.T) {
	t.Parallel()

	endpoints := New().Endpoints()
	if len(endpoints) != 4 {
		t.Fatalf("endpoints: got %d, want 4", len(endpoints))
	}

	for i, initializationEndpoint := range endpoints {
		if initializationEndpoint == nil {
			t.Errorf("nil endpoint at index %d", i)
		}
	}
}
