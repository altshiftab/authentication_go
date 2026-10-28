// Package client is an OAuth client as the authorization server knows it: what it is called and
// where it may be sent back to.
package client

import (
	"net/url"
	"slices"
)

type Client struct {
	Id   string
	Name string
	// RedirectUris are where an authorization response may go, matched exactly but for the port of
	// a loopback address (RFC 8252 section 7.3): an app on the user's own machine listens on
	// whatever port it is given.
	RedirectUris []string
	// SelfRegistered is a client that registered itself (RFC 7591): its name is what it called
	// itself, which nothing checks, and its id says nothing of who it is.
	SelfRegistered bool
}

// AllowsRedirectUri says whether the client may be sent back to the URI.
func (c *Client) AllowsRedirectUri(uri string) bool {
	if uri == "" {
		return false
	}
	if slices.Contains(c.RedirectUris, uri) {
		return true
	}

	candidate, err := url.Parse(uri)
	if err != nil || !IsLoopback(candidate) {
		return false
	}

	for _, registered := range c.RedirectUris {
		registeredUrl, err := url.Parse(registered)
		if err != nil || !IsLoopback(registeredUrl) {
			continue
		}
		if candidate.Hostname() == registeredUrl.Hostname() &&
			candidate.Path == registeredUrl.Path &&
			candidate.RawQuery == registeredUrl.RawQuery &&
			candidate.Fragment == "" {
			return true
		}
	}

	return false
}

// IsLoopback says whether the URL is an http URL on a loopback address, which an app on the user's
// own machine receives its response at. The IPv6 loopback is not one: a Content-Security-Policy can
// name no IPv6 address, so the consent page's form could not be let send the user on to it.
func IsLoopback(u *url.URL) bool {
	if u == nil || u.Scheme != "http" || u.User != nil {
		return false
	}
	switch u.Hostname() {
	case "localhost", "127.0.0.1":
		return true
	}
	return false
}
