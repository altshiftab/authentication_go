// Package log_masking keeps the credentials the authentication endpoints handle out of the log, by
// telling the log's HTTP context extractor where they are.
//
// Which query parameters carry a credential, and which calls exchange one, is knowledge of the
// endpoints rather than of each service that mounts them: a service that had to list them itself
// would have to remember every one, and one of them did not. Each endpoint says what it carries, and
// Apply puts that on the extractor.
package log_masking

import (
	"fmt"

	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/altshiftab/utils_go/pkg/http/types/http_context_extractor"
	"github.com/altshiftab/utils_go/pkg/http/types/http_context_extractor/http_context_extractor_config"
	"github.com/altshiftab/utils_go/pkg/schema"
	"github.com/altshiftab/utils_go/pkg/utils"
)

// BodyFields are what of a request's body and of a response's the log masks, by URL.
type BodyFields struct {
	Request  []*http_context_extractor_config.MaskedBodyFields
	Response []*http_context_extractor_config.MaskedBodyFields
}

// Masker is implemented by an endpoint whose requests carry a credential in their URL, or which
// exchanges one with another service, and says where.
type Masker interface {
	// MaskedUrlParams are the endpoint's URLs whose query parameters carry credentials, with the
	// parameters named in Query.
	MaskedUrlParams() []*schema.Url

	// MaskedBodyFields are what of the bodies the endpoint exchanges -- its requests', or those of
	// the calls it makes -- the log masks, field by field. It is an error for an endpoint to be asked
	// before it knows them, rather than none, so that a service that applies the masks too early
	// fails at startup instead of logging the exchange unmasked.
	MaskedBodyFields() (*BodyFields, error)

	// MaskedHeaders are the headers of the endpoint's requests that the log masks whole: those
	// carrying a token of which the log's own masking of a header -- the signature, and a session
	// token's subject -- would leave readable what identifies the person.
	MaskedHeaders() []*http_context_extractor_config.MaskedHeader
}

// Apply adds what each masker names to the extractor's masks, alongside whatever a service set
// there itself. It is called once, at startup, after the endpoints are initialized -- an endpoint
// learns some of what it carries, such as the provider's token URL, only then.
func Apply(extractor *http_context_extractor.Extractor, maskers ...Masker) error {
	if extractor == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("http context extractor"))
	}

	for i, masker := range maskers {
		if utils.IsNil(masker) {
			return altshiftErrors.NewWithTrace(fmt.Errorf("masker %d: %w", i, nil_error.New("masker")))
		}

		bodyFields, err := masker.MaskedBodyFields()
		if err != nil {
			return altshiftErrors.New(fmt.Errorf("masker %d: masked body fields: %w", i, err))
		}

		extractor.MaskedUrlParams = append(extractor.MaskedUrlParams, masker.MaskedUrlParams()...)
		extractor.MaskedHeaders = append(extractor.MaskedHeaders, masker.MaskedHeaders()...)
		if bodyFields != nil {
			extractor.MaskedRequestBodyFields = append(extractor.MaskedRequestBodyFields, bodyFields.Request...)
			extractor.MaskedResponseBodyFields = append(extractor.MaskedResponseBodyFields, bodyFields.Response...)
		}
	}

	return nil
}
