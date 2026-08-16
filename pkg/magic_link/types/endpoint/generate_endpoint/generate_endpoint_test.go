package generate_endpoint

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"net/url"
	"strings"
	"testing"

	muxPkg "github.com/Motmedel/utils_go/pkg/http/mux"
	muxTesting "github.com/Motmedel/utils_go/pkg/http/mux/testing"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail"
	magicLinkTesting "github.com/altshiftab/authentication_go/pkg/magic_link/testing"
	"github.com/altshiftab/authentication_go/pkg/magic_link/types/endpoint/generate_endpoint/generate_endpoint_config"
)

const defaultPath = "/api/login/magic/generate"

func TestEndpoint(t *testing.T) {
	t.Parallel()

	signer := magicLinkTesting.NewSigner()
	fromAddress := magicLinkTesting.MustFromAddress()
	linkBaseUrl := magicLinkTesting.MustParseUrl(magicLinkTesting.LinkBaseUrl)

	testCases := []struct {
		name              string
		args              *muxTesting.Args
		emptyEmail        bool
		invalidEmail      bool
		invalidJson       bool
		mailSenderErr     error
		nonce             string
		expectSent        bool
		expectSentAttempt bool
		expectRecvAddr    string
		accountExists     *bool
		accountErr        error
	}{
		{
			name: "success",
			args: &muxTesting.Args{
				ExpectedStatusCode: http.StatusNoContent,
			},
			nonce:          magicLinkTesting.DefaultNonce,
			expectSent:     true,
			expectRecvAddr: magicLinkTesting.ValidEmail,
		},
		{
			name: "lowercases email address",
			args: &muxTesting.Args{
				ExpectedStatusCode: http.StatusNoContent,
				Body:               []byte(`{"email_address":"Test@Example.COM"}`),
			},
			nonce:          magicLinkTesting.DefaultNonce,
			expectSent:     true,
			expectRecvAddr: magicLinkTesting.ValidEmail,
		},
		{
			name: "empty email",
			args: &muxTesting.Args{
				ExpectedStatusCode: http.StatusUnprocessableEntity,
				ExpectedProblemDetail: &problem_detail.Detail{
					Detail: "The email address is empty.",
				},
			},
			emptyEmail: true,
		},
		{
			name: "invalid email",
			args: &muxTesting.Args{
				ExpectedStatusCode: http.StatusUnprocessableEntity,
				ExpectedProblemDetail: &problem_detail.Detail{
					Detail: "The email address is invalid.",
				},
			},
			invalidEmail: true,
		},
		{
			name: "malformed json",
			args: &muxTesting.Args{
				ExpectedStatusCode: http.StatusBadRequest,
				ExpectedProblemDetail: &problem_detail.Detail{
					Detail: "Invalid JSON body.",
				},
			},
			invalidJson: true,
		},
		{
			name: "mail sender error",
			args: &muxTesting.Args{
				ExpectedStatusCode:    http.StatusInternalServerError,
				ExpectedProblemDetail: &problem_detail.Detail{},
			},
			mailSenderErr:     errors.New("smtp boom"),
			nonce:             magicLinkTesting.DefaultNonce,
			expectSentAttempt: true,
		},
		{
			name: "allowed redirect",
			args: &muxTesting.Args{
				ExpectedStatusCode: http.StatusNoContent,
				Body:               []byte(`{"email_address":"` + magicLinkTesting.ValidEmail + `","redirect":"https://app.example.com/dashboard"}`),
			},
			nonce:          magicLinkTesting.DefaultNonce,
			expectSent:     true,
			expectRecvAddr: magicLinkTesting.ValidEmail,
		},
		{
			name: "disallowed redirect",
			args: &muxTesting.Args{
				ExpectedStatusCode: http.StatusUnprocessableEntity,
				ExpectedProblemDetail: &problem_detail.Detail{
					Detail: "The redirect URL hostname is not allowed.",
				},
				Body: []byte(`{"email_address":"` + magicLinkTesting.ValidEmail + `","redirect":"https://evil.com/phish"}`),
			},
		},
		{
			name: "malformed redirect",
			args: &muxTesting.Args{
				ExpectedStatusCode: http.StatusUnprocessableEntity,
				ExpectedProblemDetail: &problem_detail.Detail{
					Detail: "The redirect URL is malformed.",
				},
				Body: []byte(`{"email_address":"` + magicLinkTesting.ValidEmail + `","redirect":":://broken"}`),
			},
		},
		{
			name: "unregistered account",
			args: &muxTesting.Args{
				ExpectedStatusCode: http.StatusNoContent,
			},
			accountExists: ptrBool(false),
		},
		{
			name: "account checker error",
			args: &muxTesting.Args{
				ExpectedStatusCode:    http.StatusInternalServerError,
				ExpectedProblemDetail: &problem_detail.Detail{},
			},
			accountErr: errors.New("db boom"),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			fakeSender := &magicLinkTesting.FakeMailSender{Err: testCase.mailSenderErr}

			accountExists := true
			if testCase.accountExists != nil {
				accountExists = *testCase.accountExists
			}
			accountErr := testCase.accountErr

			testEndpoint := New(
				generate_endpoint_config.WithAccountChecker(
					func(_ context.Context, _ string) (bool, error) { return accountExists, accountErr },
				),
			)
			if err := testEndpoint.Initialize(fakeSender, signer, fromAddress, linkBaseUrl, magicLinkTesting.Domain); err != nil {
				t.Fatalf("initialize: %v", err)
			}

			if testCase.nonce != "" {
				nonce := testCase.nonce
				testEndpoint.makeNonce = func() string { return nonce }
			}

			mux := &muxPkg.Mux{}
			mux.Add(testEndpoint.Endpoint.Endpoint)
			httpServer := httptest.NewServer(mux)
			defer httpServer.Close()

			if testCase.args.Body == nil {
				switch {
				case testCase.invalidJson:
					testCase.args.Body = []byte(`{`)
				case testCase.emptyEmail:
					testCase.args.Body = []byte(`{"email_address":""}`)
				case testCase.invalidEmail:
					testCase.args.Body = []byte(`{"email_address":"` + magicLinkTesting.InvalidEmail + `"}`)
				default:
					testCase.args.Body = []byte(`{"email_address":"` + magicLinkTesting.ValidEmail + `"}`)
				}
			}

			testCase.args.Path = testEndpoint.Path
			testCase.args.Method = testEndpoint.Method
			testCase.args.Headers = append(testCase.args.Headers, [2]string{"Content-Type", "application/json"})

			muxTesting.TestArgs(t, testCase.args, httpServer.URL)

			if testCase.expectSent {
				msg := fakeSender.Last()
				if msg == nil {
					t.Fatalf("expected message to be sent, got none")
				}

				if got := msg.From; got == nil || got.Address != fromAddress.Address {
					t.Errorf("from address: got %v, want %v", got, fromAddress)
				}

				if len(msg.To) != 1 || msg.To[0] == nil || msg.To[0].Address != testCase.expectRecvAddr {
					t.Errorf("to addresses: got %v, want [%s]", msg.To, testCase.expectRecvAddr)
				}

				body := msg.Body
				if body == nil {
					t.Fatalf("expected message body, got nil")
				}

				if !strings.Contains(string(body.Content), magicLinkTesting.LinkBaseUrl) {
					t.Errorf("body does not contain link base url: %s", string(body.Content))
				}
				if !strings.Contains(string(body.Content), "token=") {
					t.Errorf("body does not contain token query parameter: %s", string(body.Content))
				}
			} else if testCase.expectSentAttempt {
				if len(fakeSender.Messages) != 1 {
					t.Errorf("expected 1 send attempt, got %d", len(fakeSender.Messages))
				}
			} else if len(fakeSender.Messages) != 0 {
				t.Errorf("expected no messages sent, got %d", len(fakeSender.Messages))
			}
		})
	}
}

func TestEndpoint_Initialize(t *testing.T) {
	t.Parallel()

	signer := magicLinkTesting.NewSigner()
	fromAddress := magicLinkTesting.MustFromAddress()
	linkBaseUrl := magicLinkTesting.MustParseUrl(magicLinkTesting.LinkBaseUrl)

	type args struct {
		mailSender  *magicLinkTesting.FakeMailSender
		signer      any
		fromAddress *mail.Address
		linkBaseUrl *url.URL
		domain      string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "success",
			args: args{
				mailSender:  &magicLinkTesting.FakeMailSender{},
				signer:      signer,
				fromAddress: fromAddress,
				linkBaseUrl: linkBaseUrl,
				domain:      magicLinkTesting.Domain,
			},
		},
		{
			name: "nil mail sender",
			args: args{
				mailSender:  nil,
				signer:      signer,
				fromAddress: fromAddress,
				linkBaseUrl: linkBaseUrl,
				domain:      magicLinkTesting.Domain,
			},
			wantErr: true,
		},
		{
			name: "nil signer",
			args: args{
				mailSender:  &magicLinkTesting.FakeMailSender{},
				signer:      nil,
				fromAddress: fromAddress,
				linkBaseUrl: linkBaseUrl,
				domain:      magicLinkTesting.Domain,
			},
			wantErr: true,
		},
		{
			name: "nil from address",
			args: args{
				mailSender:  &magicLinkTesting.FakeMailSender{},
				signer:      signer,
				fromAddress: nil,
				linkBaseUrl: linkBaseUrl,
				domain:      magicLinkTesting.Domain,
			},
			wantErr: true,
		},
		{
			name: "nil link base url",
			args: args{
				mailSender:  &magicLinkTesting.FakeMailSender{},
				signer:      signer,
				fromAddress: fromAddress,
				linkBaseUrl: nil,
				domain:      magicLinkTesting.Domain,
			},
			wantErr: true,
		},
		{
			name: "empty domain",
			args: args{
				mailSender:  &magicLinkTesting.FakeMailSender{},
				signer:      signer,
				fromAddress: fromAddress,
				linkBaseUrl: linkBaseUrl,
				domain:      "",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			endpoint := New(
				generate_endpoint_config.WithAccountChecker(
					func(_ context.Context, _ string) (bool, error) { return true, nil },
				),
			)
			var sender *magicLinkTesting.FakeMailSender = tt.args.mailSender
			var signerArg = signer
			if tt.args.signer == nil {
				signerArg = nil
			}
			err := endpoint.Initialize(sender, signerArg, tt.args.fromAddress, tt.args.linkBaseUrl, tt.args.domain)
			if (err != nil) != tt.wantErr {
				t.Errorf("Initialize() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func ptrBool(b bool) *bool { return &b }
