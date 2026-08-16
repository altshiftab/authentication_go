package sign_in_failed_endpoint

import (
	"net/http"

	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint"
	"github.com/altshiftab/authentication_go/pkg/sso/types/endpoint/problem_detail_endpoint"
	"github.com/altshiftab/authentication_go/pkg/sso/types/endpoint/problem_detail_endpoint/problem_detail_endpoint_config"
)

// A catch-all for unexpected sign-in failures, including provider errors that
// indicate application misconfiguration (e.g. `invalid_request`,
// `unauthorized_client`, `invalid_scope`) and any unrecognized error. These
// generally warrant investigation rather than a user retry.
const (
	// DefaultType is a stable RFC 9457 problem type URI reference. Override it
	// with problem_detail_endpoint_config.WithType to a stable, dereferenceable
	// URL for your deployment.
	DefaultType   = "/sso/problems/sign-in-failed"
	DefaultTitle  = "Sign-in failed"
	DefaultDetail = "Something went wrong while signing you in. Please try again. If the problem persists, contact support."
	DefaultStatus = http.StatusInternalServerError
)

func New(options ...problem_detail_endpoint_config.Option) (*endpoint.Endpoint, error) {
	return problem_detail_endpoint.New(
		append(
			[]problem_detail_endpoint_config.Option{
				problem_detail_endpoint_config.WithPath(DefaultType),
				problem_detail_endpoint_config.WithType(DefaultType),
				problem_detail_endpoint_config.WithTitle(DefaultTitle),
				problem_detail_endpoint_config.WithDetail(DefaultDetail),
				problem_detail_endpoint_config.WithStatus(DefaultStatus),
			},
			options...,
		)...,
	)
}
