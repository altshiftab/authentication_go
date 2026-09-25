package active_session_processor

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"testing"
	"time"

	accountPkg "github.com/altshiftab/authentication_go/pkg/database/types/account"
	authenticationPkg "github.com/altshiftab/authentication_go/pkg/database/types/authentication"
	"github.com/altshiftab/authentication_go/pkg/database/types/customer"
	"github.com/altshiftab/authentication_go/pkg/session/types/active_session_processor/active_session_processor_config"
	"github.com/altshiftab/authentication_go/pkg/session/types/authorizer_request_parser"
	"github.com/altshiftab/authentication_go/pkg/session/types/authorizer_request_parser/authorizer_request_parser_config"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_token"
	altshiftCryptoEddsa "github.com/altshiftab/utils_go/pkg/crypto/eddsa"
	altshiftSqlTesting "github.com/altshiftab/utils_go/pkg/database/sql/testing"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/claims/session_claims"
)

var (
	errUnexpectedId    = errors.New("unexpected authentication id")
	errDatabaseFailure = errors.New("connection refused")
)

const (
	authenticationId = "test-authentication-id"
	accountId        = "test-account-id"
	tenantId         = "test-tenant-id"
	tenantName       = "test-tenant-name"
	adminRole        = "admin"
	superAdminRole   = "super-admin"
	otherRole        = "other"
)

func newAuthorizer(t *testing.T, options ...authorizer_request_parser_config.Option) *authorizer_request_parser.Parser {
	t.Helper()

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519 generate key: %v", err)
	}

	authorizer, err := authorizer_request_parser.New(
		&altshiftCryptoEddsa.Method{PrivateKey: privateKey, PublicKey: publicKey},
		"test-issuer",
		"test-audience",
		options...,
	)
	if err != nil {
		t.Fatalf("authorizer new: %v", err)
	}

	return authorizer
}

// A token as the authorizer passes it on: for the account, in the tenant, with the admin role.
func makeToken() *session_token.Token {
	return &session_token.Token{
		Claims: &session_claims.Claims{
			AuthorizedParty: tenantId + ":" + tenantName,
			Roles:           []string{adminRole},
		},
		AuthenticationId: authenticationId,
		SubjectId:        accountId,
		TenantId:         tenantId,
		TenantName:       tenantName,
		Roles:            []string{adminRole},
	}
}

// An authentication that stands: not ended, not expired, its account unlocked, still an admin in
// the same tenant.
func makeAuthentication() *authenticationPkg.Authentication {
	return &authenticationPkg.Authentication{
		Id:        authenticationId,
		ExpiresAt: new(time.Now().Add(time.Hour)),
		Account: &accountPkg.Account{
			Id:       accountId,
			Roles:    []string{adminRole},
			Customer: &customer.Customer{Id: tenantId, Name: tenantName},
		},
	}
}

func selectReturning(
	authentication *authenticationPkg.Authentication,
	err error,
) func(context.Context, string, *sql.DB) (*authenticationPkg.Authentication, error) {
	return func(_ context.Context, id string, _ *sql.DB) (*authenticationPkg.Authentication, error) {
		if id != authenticationId {
			return nil, fmt.Errorf("%w: %q", errUnexpectedId, id)
		}
		return authentication, err
	}
}

func TestNew(t *testing.T) {
	t.Parallel()

	authorizer := newAuthorizer(t)
	db := altshiftSqlTesting.NewDb()

	testCases := []struct {
		name       string
		authorizer *authorizer_request_parser.Parser
		db         *sql.DB
		wantErr    bool
	}{
		{name: "valid", authorizer: authorizer, db: db},
		{name: "nil authorizer", db: db, wantErr: true},
		{name: "nil db", authorizer: authorizer, wantErr: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			processor, err := New(testCase.authorizer, testCase.db)
			if testCase.wantErr {
				if err == nil {
					t.Errorf("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("new: %v", err)
			}
			if processor == nil || processor.selectAuthentication == nil {
				t.Fatalf("incomplete processor: %+v", processor)
			}
		})
	}
}

func TestProcessor_Process(t *testing.T) {
	t.Parallel()

	adminAuthorizer := newAuthorizer(
		t,
		authorizer_request_parser_config.WithAllowedRoles(adminRole),
		authorizer_request_parser_config.WithSuperAdminRoles(superAdminRole),
	)
	tenantAuthorizer := newAuthorizer(t, authorizer_request_parser_config.WithAllowedTenantId(tenantId))

	testCases := []struct {
		name           string
		cancelled      bool
		nilToken       bool
		authorizer     *authorizer_request_parser.Parser
		token          *session_token.Token
		authentication func(*authenticationPkg.Authentication)
		selectErr      error
		// wantStatus is the refusal's status; 0 for a server error, and ignored when wantPass.
		wantStatus int
		wantPass   bool
		wantRoles  []string
		wantTenant string
	}{
		{
			name:       "standing session",
			wantPass:   true,
			wantRoles:  []string{adminRole},
			wantTenant: tenantId,
		},
		{
			name: "roles and tenant are taken from the account",
			authentication: func(authentication *authenticationPkg.Authentication) {
				authentication.Account.Roles = []string{otherRole, adminRole}
				authentication.Account.Customer = &customer.Customer{Id: "new-tenant-id", Name: "new-tenant-name"}
			},
			wantPass:   true,
			wantRoles:  []string{otherRole, adminRole},
			wantTenant: "new-tenant-id",
		},
		{
			name: "super admin role admits without the allowed role",
			authentication: func(authentication *authenticationPkg.Authentication) {
				authentication.Account.Roles = []string{superAdminRole}
			},
			wantPass:   true,
			wantRoles:  []string{superAdminRole},
			wantTenant: tenantId,
		},
		{
			name: "ended authentication",
			authentication: func(authentication *authenticationPkg.Authentication) {
				authentication.Ended = true
			},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "expired authentication",
			authentication: func(authentication *authenticationPkg.Authentication) {
				authentication.ExpiresAt = new(time.Now().Add(-time.Minute))
			},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "locked account",
			authentication: func(authentication *authenticationPkg.Authentication) {
				authentication.Account.Locked = true
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name: "role taken away",
			authentication: func(authentication *authenticationPkg.Authentication) {
				authentication.Account.Roles = []string{otherRole}
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "tenant changed",
			authorizer: tenantAuthorizer,
			authentication: func(authentication *authenticationPkg.Authentication) {
				authentication.Account.Customer = &customer.Customer{Id: "other-tenant-id", Name: "other"}
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "tenant removed",
			authorizer: tenantAuthorizer,
			authentication: func(authentication *authenticationPkg.Authentication) {
				authentication.Account.Customer = nil
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "absent authentication",
			selectErr:  fmt.Errorf("sql row scan: %w", sql.ErrNoRows),
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:      "database failure",
			selectErr: errDatabaseFailure,
		},
		{
			name: "authentication of another account",
			authentication: func(authentication *authenticationPkg.Authentication) {
				authentication.Account.Id = "other-account-id"
			},
		},
		{
			name: "token without authentication id",
			token: func() *session_token.Token {
				token := makeToken()
				token.AuthenticationId = ""
				return token
			}(),
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:     "nil token",
			nilToken: true,
		},
		{
			name:      "cancelled context",
			cancelled: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			authorizer := testCase.authorizer
			if authorizer == nil {
				authorizer = adminAuthorizer
			}

			authentication := makeAuthentication()
			if testCase.authentication != nil {
				testCase.authentication(authentication)
			}
			if testCase.selectErr != nil {
				authentication = nil
			}

			processor, err := New(
				authorizer,
				altshiftSqlTesting.NewDb(),
				active_session_processor_config.WithSelectAuthentication(
					selectReturning(authentication, testCase.selectErr),
				),
			)
			if err != nil {
				t.Fatalf("new: %v", err)
			}

			ctx := t.Context()
			if testCase.cancelled {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}

			token := testCase.token
			if token == nil && !testCase.nilToken {
				token = makeToken()
			}

			result, responseError := processor.Process(ctx, token)

			if testCase.wantPass {
				if responseError != nil {
					t.Fatalf("unexpected response error: %+v", responseError)
				}
				if result == nil {
					t.Fatalf("nil result")
				}
				if !slices.Equal(result.Roles, testCase.wantRoles) {
					t.Errorf("roles: got %v, want %v", result.Roles, testCase.wantRoles)
				}
				if result.Claims == nil || !slices.Equal(result.Claims.Roles, testCase.wantRoles) {
					t.Errorf("claims roles: got %+v, want %v", result.Claims, testCase.wantRoles)
				}
				if result.TenantId != testCase.wantTenant {
					t.Errorf("tenant id: got %q, want %q", result.TenantId, testCase.wantTenant)
				}
				// The claims agree with the fields they are parsed into.
				if reparsed, err := session_token.Parse(result.Claims); err != nil || reparsed.TenantId != result.TenantId {
					t.Errorf("claims tenant: got %+v (%v), want %q", reparsed, err, result.TenantId)
				}
				// The token the authorizer produced is left as it was issued.
				if !slices.Equal(token.Roles, []string{adminRole}) || !slices.Equal(token.Claims.Roles, []string{adminRole}) {
					t.Errorf("input token was modified: %+v", token)
				}
				return
			}

			if result != nil {
				t.Errorf("expected no result, got %+v", result)
			}
			if responseError == nil {
				t.Fatalf("expected a response error")
			}

			if testCase.wantStatus == 0 {
				if responseError.ServerError == nil {
					t.Errorf("expected a server error, got %+v", responseError)
				}
				return
			}

			problemDetail := responseError.ProblemDetail
			if problemDetail == nil {
				t.Fatalf("expected a problem detail, got %+v", responseError)
			}
			if problemDetail.Status != testCase.wantStatus {
				t.Errorf("status: got %d, want %d", problemDetail.Status, testCase.wantStatus)
			}
			if responseError.ServerError != nil {
				t.Errorf("unexpected server error: %v", responseError.ServerError)
			}
		})
	}
}
