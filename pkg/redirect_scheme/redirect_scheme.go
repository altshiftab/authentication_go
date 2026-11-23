// Package redirect_scheme decides which schemes a browser may be sent on to once it is signed in.
//
// Where a sign-in sends the browser is checked by host, and the host alone says nothing about the
// scheme: a host can be read out of any URL written with an authority, so "javascript://example.com/"
// names the same host as "https://example.com/". A browser handed such a target runs it, hands it to
// an app, or follows it over a connection anyone on the path can read. Only https is a destination,
// and http only where the service is run on the machine itself.
package redirect_scheme

import (
	"net"
	"net/url"

	altshiftNet "github.com/altshiftab/utils_go/pkg/net"
)

// Allowed reports whether a signed-in browser may be sent to target: over https, or over plain http
// to a loopback host where allowLoopbackHttp says the service is run locally.
func Allowed(target *url.URL, allowLoopbackHttp bool) bool {
	if target == nil {
		return false
	}

	switch target.Scheme {
	case "https":
		return true
	case "http":
		return allowLoopbackHttp && IsLoopback(target.Hostname())
	default:
		return false
	}
}

// IsLoopback reports whether hostname is this machine: localhost or a name under it, or a loopback
// address.
func IsLoopback(hostname string) bool {
	if altshiftNet.IsLocalhost(hostname) {
		return true
	}

	ip := net.ParseIP(hostname)
	return ip != nil && ip.IsLoopback()
}
