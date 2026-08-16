package authentication

import (
	"time"

	"github.com/altshiftab/authentication_go/pkg/database/types/account"
)

type Authentication struct {
	Id               string           `postgres:"id,primarykey,type:uuid,default:gen_random_uuid()"`
	Account          *account.Account `postgres:"account,ondelete:CASCADE"`
	IdTokenHash      []byte           `postgres:"id_token_hash,unique,nullable"`
	DbscPublicKey    []byte           `postgres:"dbsc_public_key,nullable"`
	CreatedAt        *time.Time       `postgres:"created_at"`
	ExpiresAt        *time.Time       `postgres:"expires_at"`
	Ended            bool             `postgres:"ended,default:false"`
	EndedAt          *time.Time       `postgres:"ended_at,nullable"`
	IpAddress        string           `postgres:"ip_address,type:inet,nullable"`
	IpAddressCountry string           `postgres:"ip_address_country,nullable"`
	IpAddressCity    string           `postgres:"ip_address_city,nullable"`
	UserAgent        string           `postgres:"user_agent,nullable"`
}

// ClientMetadata holds request-derived client information persisted alongside an
// authentication. It is extracted from the HTTP context (see the session
// manager) and passed to InsertAuthentication.
type ClientMetadata struct {
	IpAddress        string
	IpAddressCountry string
	IpAddressCity    string
	UserAgent        string
}
