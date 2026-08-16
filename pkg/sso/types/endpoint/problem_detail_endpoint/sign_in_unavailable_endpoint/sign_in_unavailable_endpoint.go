package sign_in_unavailable_endpoint

import (
	"net/http"

	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint"
	"github.com/altshiftab/authentication_go/pkg/sso/types/endpoint/problem_detail_endpoint"
	"github.com/altshiftab/authentication_go/pkg/sso/types/endpoint/problem_detail_endpoint/problem_detail_endpoint_config"
)

// The provider reported a transient failure (OAuth `server_error` or
// `temporarily_unavailable`). The condition is expected to clear on its own, so
// the user should be invited to try again shortly.
const (
	// DefaultType is a stable RFC 9457 problem type URI reference. Override it
	// with problem_detail_endpoint_config.WithType to a stable, dereferenceable
	// URL for your deployment.
	DefaultType   = "/sso/problems/sign-in-unavailable"
	DefaultTitle  = "Sign-in temporarily unavailable"
	DefaultDetail = "The sign-in provider is temporarily unavailable. Please try again in a few minutes."
	DefaultStatus = http.StatusServiceUnavailable
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
