package sign_in_unavailable_endpoint

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	muxPkg "github.com/Motmedel/utils_go/pkg/http/mux"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail"
)

func TestEndpoint(t *testing.T) {
	t.Parallel()

	testEndpoint, err := New()
	if err != nil {
		t.Fatalf("new endpoint: %v", err)
	}

	mux := &muxPkg.Mux{}
	mux.Add(testEndpoint)
	server := httptest.NewServer(mux)
	defer server.Close()

	request, err := http.NewRequest(http.MethodGet, server.URL+DefaultType, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	request.Header.Set("Accept", "application/problem+json")

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("client do: %v", err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != DefaultStatus {
		t.Errorf("status = %d, want %d", response.StatusCode, DefaultStatus)
	}

	body, _ := io.ReadAll(response.Body)
	var detail problem_detail.Detail
	if err := json.Unmarshal(body, &detail); err != nil {
		t.Fatalf("unmarshal problem detail: %v (body: %s)", err, body)
	}
	if detail.Type != DefaultType {
		t.Errorf("type = %q, want %q", detail.Type, DefaultType)
	}
	if detail.Title != DefaultTitle {
		t.Errorf("title = %q, want %q", detail.Title, DefaultTitle)
	}
	if detail.Detail != DefaultDetail {
		t.Errorf("detail = %q, want %q", detail.Detail, DefaultDetail)
	}
	if detail.Status != DefaultStatus {
		t.Errorf("status field = %d, want %d", detail.Status, DefaultStatus)
	}
}
