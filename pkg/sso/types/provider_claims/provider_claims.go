package provider_claims

import (
	"fmt"
	"slices"
	"strings"

	ssoErrors "github.com/altshiftab/authentication_go/pkg/sso/errors"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
)

type ProviderClaims interface {
	VerifiedEmailAddress() (string, error)
	// AuthenticationContext reports how the provider says it authenticated the user. It is nil when
	// the provider said nothing, which is not the same as saying no second factor was used.
	AuthenticationContext() *AuthenticationContext
	// Subject is the provider's stable identifier for the account, which distinguishes one user
	// from another without depending on the email address.
	Subject() string
	// OrganizationIdentifier names the organization the account belongs to: the hosted domain for
	// Google, the tenant for Microsoft. It is empty for an account that belongs to no organization,
	// such as a personal Google account, which is what makes it usable to keep consumer accounts
	// out.
	OrganizationIdentifier() string
}

// AuthenticationContext holds what an identity provider states about an authentication event. The
// claims are only present when the provider is asked for them and chooses to supply them.
type AuthenticationContext struct {
	// MethodReferences is the "amr" claim: the methods used, such as pwd, otp, hwk or mfa.
	MethodReferences []string
	// ContextClass is the "acr" claim: the level the authentication reached.
	ContextClass string
	// AuthenticatedAt is the "auth_time" claim: when the user actually authenticated, which may be
	// well before the token was issued if the provider reused an existing session.
	AuthenticatedAt int64
}

// StrongAuthenticationMethodReferences are the "amr" values taken to mean the sign-in was at least
// as strong as multi-factor.
//
// Two kinds are listed. "mfa" and "multipleauthn" are the providers' own statements that more than
// one factor was used. The rest are single-step methods that are nonetheless no weaker: a passkey or
// security key proves possession of a device and is unphishable, and providers report it without
// saying "mfa" — Google as "swk" or "hwk", Microsoft as "fido" or "fido2". Requiring "mfa" alone
// would therefore refuse the strongest sign-ins while admitting a password with an SMS code.
//
// Deliberately absent: "wia" is merely an existing Windows session, and "x509", "cert" and
// "smartcard" do not by themselves say whether the credential was unlocked. Deployments that treat
// those as sufficient can say so.
//
// TODO: Narrow this to the unphishable methods, dropping "mfa" and "multipleauthn". A one-time code
// sent by SMS is not a strong factor, being both phishable and interceptable, but the providers
// report such a sign-in as "mfa", so accepting "mfa" accepts SMS along with it. Left as is until the
// sign-in logs show which methods are in use, since narrowing it refuses everyone whose second
// factor is a code.
var StrongAuthenticationMethodReferences = []string{"mfa", "multipleauthn", "fido", "fido2", "hwk", "swk"}

// HasAnyMethodReference reports whether the provider stated any of the given methods. A nil context,
// or one without method references, reports false: a provider that said nothing is not evidence of
// anything, and a caller requiring a method should treat it as unproven.
func (c *AuthenticationContext) HasAnyMethodReference(methodReferences []string) bool {
	if c == nil {
		return false
	}

	for _, stated := range c.MethodReferences {
		if slices.Contains(methodReferences, strings.ToLower(stated)) {
			return true
		}
	}

	return false
}

// StrongAuthentication reports whether the sign-in was at least as strong as multi-factor, by
// StrongAuthenticationMethodReferences.
func (c *AuthenticationContext) StrongAuthentication() bool {
	return c.HasAnyMethodReference(StrongAuthenticationMethodReferences)
}

type GoogleClaims struct {
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	Sub           string   `json:"sub"`
	Hd            string   `json:"hd"`
	Amr           []string `json:"amr,omitzero"`
	Acr           string   `json:"acr,omitzero"`
	AuthTime      int64    `json:"auth_time,omitzero"`
}

func (c *GoogleClaims) Subject() string {
	return c.Sub
}

// OrganizationIdentifier returns the "hd" claim, the Google Workspace domain hosting the account.
// Google omits it for consumer accounts, so an empty value means the account is a personal one.
func (c *GoogleClaims) OrganizationIdentifier() string {
	return c.Hd
}

func (c *GoogleClaims) AuthenticationContext() *AuthenticationContext {
	return &AuthenticationContext{MethodReferences: c.Amr, ContextClass: c.Acr, AuthenticatedAt: c.AuthTime}
}

func (c *GoogleClaims) VerifiedEmailAddress() (string, error) {
	if c.Email == "" {
		return "", altshiftErrors.NewWithTrace(
			fmt.Errorf("%w (email address is empty)", ssoErrors.ErrForbiddenUser),
		)
	}

	if !c.EmailVerified {
		return "", altshiftErrors.NewWithTrace(
			fmt.Errorf("%w (email address not verified)", ssoErrors.ErrForbiddenUser),
		)
	}

	return c.Email, nil
}

type MicrosoftClaims struct {
	Email             string   `json:"email"`
	PreferredUsername string   `json:"preferred_username"`
	Upn               string   `json:"upn"`
	Sub               string   `json:"sub"`
	Tid               string   `json:"tid"`
	Amr               []string `json:"amr,omitzero"`
	Acr               string   `json:"acr,omitzero"`
	AuthTime          int64    `json:"auth_time,omitzero"`
}

func (c *MicrosoftClaims) Subject() string {
	return c.Sub
}

// ConsumerTenantIdentifier is the fixed tenant that personal Microsoft accounts belong to. It is a
// tenant in form only: no organization administers it, so an account in it is a personal account.
const ConsumerTenantIdentifier = "9188040d-6c67-4c5b-b112-36a304b66dad"

// OrganizationIdentifier returns the "tid" claim, the Entra tenant the account belongs to. Unlike
// Google, which simply omits the hosted domain for a personal account, Microsoft gives personal
// accounts the consumer tenant; it is reported as no organization so that both providers answer
// the question the same way.
func (c *MicrosoftClaims) OrganizationIdentifier() string {
	if strings.EqualFold(c.Tid, ConsumerTenantIdentifier) {
		return ""
	}

	return c.Tid
}

func (c *MicrosoftClaims) AuthenticationContext() *AuthenticationContext {
	return &AuthenticationContext{MethodReferences: c.Amr, ContextClass: c.Acr, AuthenticatedAt: c.AuthTime}
}

func (c *MicrosoftClaims) VerifiedEmailAddress() (string, error) {
	if c.Email == "" {
		return "", altshiftErrors.NewWithTrace(
			fmt.Errorf("%w (email address is empty)", ssoErrors.ErrForbiddenUser),
		)
	}

	return c.Email, nil
}
