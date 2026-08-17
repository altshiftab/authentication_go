package sign_in_cancelled_endpoint

import (
	"net/http"

	"github.com/altshiftab/authentication_go/pkg/sso/types/endpoint/problem_detail_endpoint"
	"github.com/altshiftab/authentication_go/pkg/sso/types/endpoint/problem_detail_endpoint/problem_detail_endpoint_config"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/endpoint"
)

// The user declined consent or otherwise cancelled the sign-in at the provider
// (e.g. OAuth `access_denied` with Microsoft `error_subcode=cancel`). The
// outcome is expected and recoverable: the user can simply try again.
const (
	// DefaultType is a stable RFC 9457 problem type URI reference. Override it
	// with problem_detail_endpoint_config.WithType to a stable, dereferenceable
	// URL for your deployment.
	DefaultType   = "/sso/problems/sign-in-cancelled"
	DefaultTitle  = "Sign-in cancelled"
	DefaultDetail = "The sign-in was cancelled. You can return to the sign-in page and try again."
	DefaultStatus = http.StatusBadRequest
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
