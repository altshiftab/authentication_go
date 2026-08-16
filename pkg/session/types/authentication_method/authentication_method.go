package authentication_method

type AuthenticationMethod = string

const (
	Refresh   AuthenticationMethod = "rtoken"
	Dbsc      AuthenticationMethod = "hwk"
	Sso       AuthenticationMethod = "ext"
	MagicLink AuthenticationMethod = "otp"
)
