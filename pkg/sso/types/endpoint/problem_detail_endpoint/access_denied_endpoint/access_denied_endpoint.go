package access_denied_endpoint

import (
	"net/http"

	"github.com/altshiftab/authentication_go/pkg/sso/types/endpoint/problem_detail_endpoint"
	"github.com/altshiftab/authentication_go/pkg/sso/types/endpoint/problem_detail_endpoint/problem_detail_endpoint_config"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/endpoint"
)

// The provider authenticated the user but a policy denies access to the
// application (e.g. the account is outside the tenant, is not assigned to the
// app, or a Workspace admin policy blocks it). Retrying does not help, so the
// page should not offer an automatic retry.
const (
	// DefaultType is a stable RFC 9457 problem type URI reference. Override it
	// with problem_detail_endpoint_config.WithType to a stable, dereferenceable
	// URL for your deployment.
	DefaultType   = "/sso/problems/access-denied"
	DefaultTitle  = "Access denied"
	DefaultDetail = "Your account is not permitted to access this application. Contact your administrator if you believe this is a mistake."
	DefaultStatus = http.StatusForbidden
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
