// Package authentication_method names how a session's holder proved who they are, as the "amr"
// claim carries it. The values are the ones RFC 8176 registers, so that a token says what it says
// to anything that reads JOSE rather than only to this library.
package authentication_method

type AuthenticationMethod = string

const (
	Refresh   AuthenticationMethod = "rtoken"
	Dbsc      AuthenticationMethod = "hwk"
	Sso       AuthenticationMethod = "ext"
	MagicLink AuthenticationMethod = "otp"

	// ApiKey is possession of a key the holder keeps in software: a file on a build runner, a
	// secret in a key manager. RFC 8176 separates that from "hwk", which Dbsc above is, because
	// the two are worth different amounts -- a hardware key cannot be copied off the machine.
	// Nothing here can tell them apart, so a key registered by an account is the software one.
	ApiKey AuthenticationMethod = "swk"
)
