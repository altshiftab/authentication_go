// Package session_instructions holds the session instructions a server returns to a browser for a
// device bound session. Both the registration and the refresh endpoint return them: registration to
// establish a session, refresh to optionally update one or, with Continue set to false, to end it.
package session_instructions

type ScopeSpecification struct {
	Type   string `json:"type,omitzero"`
	Domain string `json:"domain,omitzero"`
	Path   string `json:"path,omitzero"`
}

type Scope struct {
	Origin string `json:"origin,omitzero"`
	// IncludeSite is required by the protocol, so it is emitted even when false.
	IncludeSite        bool                  `json:"include_site"`
	ScopeSpecification []*ScopeSpecification `json:"scope_specification,omitzero"`
}

type Credential struct {
	Type       string `json:"type,omitzero"`
	Name       string `json:"name,omitzero"`
	Attributes string `json:"attributes,omitzero"`
}

type Instructions struct {
	SessionIdentifier string        `json:"session_identifier,omitzero"`
	RefreshURL        string        `json:"refresh_url,omitzero"`
	Scope             *Scope        `json:"scope,omitzero"`
	Credentials       []*Credential `json:"credentials,omitzero"`
	// AllowedRefreshInitiators restricts which hosts may initiate a refresh. Empty places no
	// restriction.
	AllowedRefreshInitiators []string `json:"allowed_refresh_initiators,omitzero"`
	// Continue indicates whether the session still applies. It defaults to true when absent, so it
	// is a pointer: only an explicit false ends the session, and the other fields may then be
	// omitted.
	Continue *bool `json:"continue,omitzero"`
}

// Ended returns the instructions that tell a browser to stop applying a session and discard its
// key, which is how a server ends a device bound session.
func Ended() *Instructions {
	sessionContinues := false
	return &Instructions{Continue: &sessionContinues}
}
