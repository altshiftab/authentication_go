package authorize_endpoint

import (
	"net/http"
	"testing"

	"github.com/altshiftab/authentication_go/pkg/oauth"
	"github.com/altshiftab/authentication_go/pkg/oauth/types/client_resolver"
	"github.com/altshiftab/authentication_go/pkg/oauth/types/memory_store"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_token"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/response_error"
)

// The flow is tested end to end in the oauth package; what is here is the endpoint's own setup.
func TestEndpoint_Initialize(t *testing.T) {
	t.Parallel()

	authorizer := request_parser.New(func(*http.Request) (*session_token.Token, *response_error.ResponseError) { return nil, nil })
	resources := []*oauth.Resource{{Url: "https://vocab.example.test/mcp", Scopes: []string{"vocab"}}}
	clients := client_resolver.New(nil, nil)
	store := memory_store.New()

	testCases := []struct {
		name       string
		authorizer request_parser.RequestParser[*session_token.Token]
		issuer     string
		clients    ClientResolver
		store      oauth.Store
		resources  []*oauth.Resource
		wantErr    bool
	}{
		{name: "complete", authorizer: authorizer, issuer: "https://i", clients: clients, store: store, resources: resources},
		{name: "no authorizer", issuer: "https://i", clients: clients, store: store, resources: resources, wantErr: true},
		{name: "no issuer", authorizer: authorizer, clients: clients, store: store, resources: resources, wantErr: true},
		{name: "no clients", authorizer: authorizer, issuer: "https://i", store: store, resources: resources, wantErr: true},
		{name: "no store", authorizer: authorizer, issuer: "https://i", clients: clients, resources: resources, wantErr: true},
		{name: "no resources", authorizer: authorizer, issuer: "https://i", clients: clients, store: store, wantErr: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			endpoint := New()
			err := endpoint.Initialize(testCase.authorizer, testCase.issuer, testCase.clients, testCase.store, testCase.resources)
			if (err != nil) != testCase.wantErr {
				t.Errorf("%s: err %v, want an error %t", testCase.name, err, testCase.wantErr)
			}
			if err == nil && (!endpoint.Initialized || endpoint.AuthenticationParser == nil || endpoint.DecisionPath != DefaultDecisionPath) {
				t.Errorf("%s: endpoint %+v", testCase.name, endpoint)
			}
		})
	}
}
