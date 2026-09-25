// Package active_session_processor checks, against the database, that a session token an
// authorizer has accepted may still be acted on.
//
// An authorizer judges a token by its signature, its expiry and what it claims, and a token is
// short-lived so that what it claims is never far out of date. Never far is still up to its
// lifetime: a sign-in ended from the account page, a locked account and a role taken away all
// take effect at the next refresh, and until then the token goes on working. For most endpoints
// that is the trade the short lifetime is for. For an endpoint whose effect outlasts the token --
// one that registers a credential, or grants a role -- it is not, since what is done in the window
// is not undone when the window closes.
//
// Such an endpoint puts this processor after its authorizer:
//
//	request_parser.NewWithProcessor(authorizer, active_session_processor.New(authorizer, db))
//
// It reads the token's authentication with its account, holds it to the rules a refresh holds it
// to, and asks the authorizer's own role and tenant question of what the account is now. The token
// it passes on carries the account's current roles and tenant, so that a handler deciding from
// them decides from what is true rather than from what was.
package active_session_processor

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	authenticationPkg "github.com/altshiftab/authentication_go/pkg/database/types/authentication"
	sessionErrors "github.com/altshiftab/authentication_go/pkg/session/errors"
	"github.com/altshiftab/authentication_go/pkg/session/types/active_session_processor/active_session_processor_config"
	"github.com/altshiftab/authentication_go/pkg/session/types/authorizer_request_parser"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_token"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/processor"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/response_error"
	"github.com/altshiftab/utils_go/pkg/http/types/problem_detail"
	"github.com/altshiftab/utils_go/pkg/http/types/problem_detail/problem_detail_config"
)

var _ processor.Processor[*session_token.Token, *session_token.Token] = (*Processor)(nil)

// ErrAccountMismatch is an authentication that belongs to an account other than the token's
// subject.
var ErrAccountMismatch = errors.New("the authentication's account is not the session token's subject")

type Processor struct {
	// Authorizer is the one the token was accepted by, whose role and tenant question is asked
	// again of the account.
	Authorizer *authorizer_request_parser.Parser
	Db         *sql.DB

	selectAuthentication func(ctx context.Context, id string, database *sql.DB) (*authenticationPkg.Authentication, error)
}

func unauthorized(err error, detail string) *response_error.ResponseError {
	return &response_error.ResponseError{
		ClientError:   err,
		ProblemDetail: problem_detail.New(http.StatusUnauthorized, problem_detail_config.WithDetail(detail)),
	}
}

func forbidden(err error, detail string) *response_error.ResponseError {
	return &response_error.ResponseError{
		ClientError:   err,
		ProblemDetail: problem_detail.New(http.StatusForbidden, problem_detail_config.WithDetail(detail)),
	}
}

func (p *Processor) Process(
	ctx context.Context,
	sessionToken *session_token.Token,
) (*session_token.Token, *response_error.ResponseError) {
	if err := ctx.Err(); err != nil {
		return nil, &response_error.ResponseError{ServerError: fmt.Errorf("context err: %w", err)}
	}

	if sessionToken == nil {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(nil_error.New("session token")),
		}
	}

	authorizer := p.Authorizer
	if authorizer == nil {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(nil_error.New("authorizer")),
		}
	}

	db := p.Db
	if db == nil {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(nil_error.New("sql db")),
		}
	}

	selectAuthentication := p.selectAuthentication
	if selectAuthentication == nil {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(nil_error.New("select authentication")),
		}
	}

	// A token with no authentication to look up is one this check cannot vouch for, and a check
	// that cannot vouch refuses.
	authenticationId := sessionToken.AuthenticationId
	if authenticationId == "" {
		return nil, unauthorized(
			altshiftErrors.NewWithTrace(empty_error.New("session token authentication id")),
			"The session token names no authentication.",
		)
	}

	authentication, err := selectAuthentication(ctx, authenticationId, db)
	if err != nil {
		// Deleting an account deletes its authentications with it, so an absent row is a session
		// that has ended as surely as one marked so.
		if errors.Is(err, sql.ErrNoRows) {
			return nil, unauthorized(
				altshiftErrors.New(fmt.Errorf("select authentication: %w", err), authenticationId),
				"The session's authentication has ended.",
			)
		}
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.New(fmt.Errorf("select authentication: %w", err), authenticationId),
		}
	}
	if authentication == nil {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(nil_error.New("authentication")),
		}
	}

	if err := session_token.VerifyAuthentication(authentication); err != nil {
		// The id rather than the row: a refusal is logged, and a holder can replay a refused token
		// for as long as they like, so the account's details are kept out of it.
		wrappedErr := altshiftErrors.New(fmt.Errorf("verify authentication: %w", err), authenticationId)
		switch {
		case errors.Is(err, sessionErrors.ErrEndedAuthentication):
			return nil, unauthorized(wrappedErr, "The session's authentication has ended.")
		case errors.Is(err, sessionErrors.ErrExpiredAuthentication):
			return nil, unauthorized(wrappedErr, "The session's authentication has expired.")
		case errors.Is(err, sessionErrors.ErrLockedAccount):
			return nil, forbidden(wrappedErr, "The account is locked.")
		}
		return nil, &response_error.ResponseError{ServerError: wrappedErr}
	}

	// VerifyAuthentication has established it.
	account := authentication.Account

	// The token's signature vouches for its subject, so an authentication belonging to another
	// account is not a client's mistake but a record that has come apart from what was issued.
	if account.Id != sessionToken.SubjectId {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(
				ErrAccountMismatch,
				account.Id, sessionToken.SubjectId,
			),
		}
	}

	var tenantId, tenantName string
	if customer := account.Customer; customer != nil {
		tenantId = customer.Id
		tenantName = customer.Name
	}

	if err := authorizer.Admits(account.Roles, tenantId); err != nil {
		wrappedErr := altshiftErrors.New(fmt.Errorf("authorizer admits: %w", err), account.Roles, tenantId)
		switch {
		case errors.Is(err, sessionErrors.ErrTenantNotAllowed):
			return nil, forbidden(wrappedErr, "The account's tenant id does not match the allowed tenant id.")
		case errors.Is(err, sessionErrors.ErrRolesNotAllowed):
			return nil, forbidden(wrappedErr, "None of the account's roles match the allowed roles.")
		}
		return nil, &response_error.ResponseError{ServerError: wrappedErr}
	}

	// The token passed on says what the account is now. It is a copy: the one the authorizer
	// produced is left as it was issued.
	current := *sessionToken
	current.Roles = slices.Clone(account.Roles)
	current.TenantId = tenantId
	current.TenantName = tenantName
	if claims := sessionToken.Claims; claims != nil {
		currentClaims := *claims
		currentClaims.Roles = slices.Clone(account.Roles)
		currentClaims.AuthorizedParty = ""
		if tenantId != "" || tenantName != "" {
			currentClaims.AuthorizedParty = strings.Join([]string{tenantId, tenantName}, ":")
		}
		current.Claims = &currentClaims
	}

	return &current, nil
}

func New(
	authorizer *authorizer_request_parser.Parser,
	db *sql.DB,
	options ...active_session_processor_config.Option,
) (*Processor, error) {
	if authorizer == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("authorizer"))
	}

	if db == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("sql db"))
	}

	config := active_session_processor_config.New(options...)

	return &Processor{
		Authorizer:           authorizer,
		Db:                   db,
		selectAuthentication: config.SelectAuthentication,
	}, nil
}
