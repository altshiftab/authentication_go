package client_id_endpoint

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Motmedel/utils_go/pkg/errors/types/empty_error"
	muxPkg "github.com/Motmedel/utils_go/pkg/http/mux"
	muxTesting "github.com/Motmedel/utils_go/pkg/http/mux/testing"
	motmedelTestingCmp "github.com/Motmedel/utils_go/pkg/testing/cmp"
)

const (
	defaultPath     = "/client-id"
	defaultClientId = "test-client-id"
)

func TestEndpoint(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		args *muxTesting.Args
	}{
		{
			name: "success",
			args: &muxTesting.Args{
				ExpectedStatusCode: http.StatusOK,
				ExpectedHeaders: [][2]string{
					{"Content-Type", "text/plain"},
				},
				ExpectedBody: []byte(defaultClientId),
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			testEndpoint, err := New(defaultPath)
			if err != nil {
				t.Fatalf("new endpoint: %v", err)
			}

			if err := testEndpoint.Initialize(defaultClientId); err != nil {
				t.Fatalf("test endpoint initialize: %v", err)
			}

			mux := &muxPkg.Mux{}
			mux.Add(testEndpoint.Endpoint.Endpoint)
			httpServer := httptest.NewServer(mux)
			defer httpServer.Close()

			testCase.args.Path = testEndpoint.Path
			testCase.args.Method = testEndpoint.Method

			muxTesting.TestArgs(t, testCase.args, httpServer.URL)
		})
	}
}

func TestInitialize(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		clientId string
		wantErr  error
	}{
		{
			name:     "valid arguments",
			clientId: defaultClientId,
		},
		{
			name:     "empty client id",
			clientId: "",
			wantErr:  empty_error.New("client id"),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			testEndpoint, err := New(defaultPath)
			if err != nil {
				t.Fatalf("new endpoint: %v", err)
			}

			err = testEndpoint.Initialize(testCase.clientId)
			motmedelTestingCmp.CompareErr(t, err, testCase.wantErr)
		})
	}
}

func TestNew(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		path    string
		wantErr error
	}{
		{
			name: "valid path",
			path: defaultPath,
		},
		{
			name:    "empty path",
			path:    "",
			wantErr: empty_error.New("path"),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			_, err := New(testCase.path)
			motmedelTestingCmp.CompareErr(t, err, testCase.wantErr)
		})
	}
}
