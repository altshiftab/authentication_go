package oauth_flow

import "time"

type Flow struct {
	Id           string     `json:"id" postgres:"id,primarykey,type:uuid,default:gen_random_uuid()"`
	CodeVerifier string     `postgres:"code_verifier,unique"`
	State        string     `postgres:"state"`
	ExpiresAt    *time.Time `postgres:"expires_at"`
	RedirectUrl  string     `postgres:"redirect_url"`
}
