package endpoint

import (
	"github.com/altshiftab/authentication_go/pkg/session/types/endpoint/dbsc_refresh_endpoint"
	"github.com/altshiftab/authentication_go/pkg/session/types/endpoint/dbsc_register_endpoint"
	"github.com/altshiftab/authentication_go/pkg/session/types/endpoint/end_endpoint"
	"github.com/altshiftab/authentication_go/pkg/session/types/endpoint/refresh_endpoint"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/endpoint/initialization_endpoint"
)

type Overview struct {
	RefreshEndpoint      *refresh_endpoint.Endpoint
	EndEndpoint          *end_endpoint.Endpoint
	DbscRefreshEndpoint  *dbsc_refresh_endpoint.Endpoint
	DbscRegisterEndpoint *dbsc_register_endpoint.Endpoint
}

func (overview *Overview) Endpoints() []*initialization_endpoint.Endpoint {
	return []*initialization_endpoint.Endpoint{
		overview.RefreshEndpoint.Endpoint,
		overview.EndEndpoint.Endpoint,
		overview.DbscRefreshEndpoint.Endpoint,
		overview.DbscRegisterEndpoint.Endpoint,
	}
}

func New() *Overview {
	return &Overview{
		RefreshEndpoint:      refresh_endpoint.New(),
		EndEndpoint:          end_endpoint.New(),
		DbscRefreshEndpoint:  dbsc_refresh_endpoint.New(),
		DbscRegisterEndpoint: dbsc_register_endpoint.New(),
	}
}
