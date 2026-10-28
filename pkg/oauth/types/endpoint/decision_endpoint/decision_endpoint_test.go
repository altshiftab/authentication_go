package decision_endpoint

import (
	"net/http"
	"testing"

	"github.com/altshiftab/authentication_go/pkg/oauth/types/memory_store"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_token"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/response_error"
)

// The flow is tested end to end in the oauth package; what is here is the endpoint's own setup,
// and what it has the log mask.
func TestEndpoint(t *testing.T) {
	t.Parallel()

	authorizer := request_parser.New(func(*http.Request) (*session_token.Token, *response_error.ResponseError) { return nil, nil })

	if err := New().Initialize(nil, "https://i", memory_store.New()); err == nil {
		t.Error("initialized without an authorizer")
	}
	if err := New().Initialize(authorizer, "", memory_store.New()); err == nil {
		t.Error("initialized without an issuer")
	}
	if err := New().Initialize(authorizer, "https://i", nil); err == nil {
		t.Error("initialized without a store")
	}

	endpoint := New()
	if err := endpoint.Initialize(authorizer, "https://i", memory_store.New()); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	// The Location the user is sent back with carries the code.
	headers := endpoint.MaskedHeaders()
	if len(headers) != 1 || headers[0].Url == nil || headers[0].Url.Path != DefaultPath || len(headers[0].Headers) != 1 || headers[0].Headers[0] != "Location" {
		t.Errorf("masked headers %+v", headers)
	}
	if bodyFields, err := endpoint.MaskedBodyFields(); err != nil || bodyFields != nil {
		t.Errorf("masked body fields %+v, %v", bodyFields, err)
	}
	if urlParams := endpoint.MaskedUrlParams(); len(urlParams) != 0 {
		t.Errorf("masked url params %+v", urlParams)
	}
}
