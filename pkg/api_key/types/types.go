// Package types holds what the API key endpoints take and answer with.
package types

import "time"

// ApiKey is a public key an account registered to mint tokens with, as the settings page lists it.
//
// The key material is not in it. What the page shows is which key, what it does and whether it
// still works; the bytes are only ever read by the service verifying a signature against them.
type ApiKey struct {
	// Id is the key's RFC 7638 thumbprint, which is what a client puts in the "sub" of an assertion
	// and what the page shows so the two can be matched by eye.
	Id        string     `json:"id" jsonschema:"id"`
	Name      string     `json:"name" jsonschema:"name"`
	Algorithm string     `json:"algorithm" jsonschema:"algorithm"`
	CreatedAt *time.Time `json:"created_at" jsonschema:"created_at"`

	ExpiresAt  *time.Time `json:"expires_at,omitzero" jsonschema:"expires_at,optional"`
	LastUsedAt *time.Time `json:"last_used_at,omitzero" jsonschema:"last_used_at,optional"`
	RevokedAt  *time.Time `json:"revoked_at,omitzero" jsonschema:"revoked_at,optional"`
}

// CreateApiKey registers a key: the public half, and a name to know it by.
//
// No proof that the account holds the private half is asked for, which is what every service that
// takes an SSH key does too. The proof would only stop a key being registered by somebody who
// talked the account into pasting one -- an attacker who has the session registers a key of their
// own and proves it perfectly well -- and it would cost every honest registration a trip through a
// terminal. What answers both cases is telling the account that a key was registered.
type CreateApiKey struct {
	Name string `json:"name" jsonschema:"name"`

	// PublicKey is PEM, as openssl, ssh-keygen and every key manager write it.
	PublicKey string `json:"public_key" jsonschema:"public_key"`

	ExpiresAt *time.Time `json:"expires_at,omitzero" jsonschema:"expires_at,optional"`
}

// Token is what the mint endpoint answers with, in the shape OAuth 2 taught every client to read.
type Token struct {
	AccessToken string `json:"access_token" jsonschema:"access_token"`
	TokenType   string `json:"token_type" jsonschema:"token_type"`
	ExpiresIn   int    `json:"expires_in" jsonschema:"expires_in"`
}
