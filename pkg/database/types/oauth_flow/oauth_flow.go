package oauth_flow

import "time"

type Flow struct {
	Id           string `json:"id" postgres:"id,primarykey,type:uuid,default:gen_random_uuid()"`
	CodeVerifier string `postgres:"code_verifier,unique"`
	// Indexed: a callback that brings no flow cookie removes an expired flow by its state.
	State string `postgres:"state,indexed"`
	// Indexed: every flow begun removes the ones that expired long enough ago.
	ExpiresAt   *time.Time `postgres:"expires_at,indexed"`
	RedirectUrl string     `postgres:"redirect_url"`
}
