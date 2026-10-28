// Package page is the authorization server's pages: the consent page, and the message a request
// is refused with where it cannot be sent back to its client.
package page

import (
	"bytes"
	"fmt"
	"html/template"
	"net"
	"net/url"
	"strings"

	"github.com/altshiftab/authentication_go/pkg/oauth/types/client"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	muxResponse "github.com/altshiftab/utils_go/pkg/http/mux/types/response"
)

const style = `body{font-family:system-ui,sans-serif;max-width:32rem;margin:3rem auto;padding:0 1rem;line-height:1.5}` +
	`dt{font-weight:600}dd{margin:0 0 .75rem;word-break:break-all}` +
	`.warning{background:#fff3cd;padding:.5rem .75rem;border-radius:4px}` +
	`button{font:inherit;padding:.5rem 1.25rem;margin-right:.5rem;cursor:pointer}`

var consentTemplate = template.Must(template.New("consent").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Allow {{.ClientName}}?</title>
<style>` + style + `</style>
</head>
<body>
<main>
<h1>Allow {{.ClientName}} to use {{.ResourceName}}?</h1>
<p>{{.ClientName}} is asking to act for you on {{.ResourceName}}. It gets nothing else of your account.</p>
<dl>
{{if .SelfRegistered}}<dt>Application</dt><dd>{{.ClientName}}, as it calls itself: it registered here on its own, and nothing vouches for the name</dd>
{{else}}<dt>Application</dt><dd>{{.ClientName}} ({{.ClientId}})</dd>
{{end}}
<dt>Sent back to</dt><dd>{{.RedirectHost}}</dd>
<dt>Access</dt><dd>{{.ResourceName}} ({{.ResourceUrl}}), {{.Scope}}</dd>
</dl>
{{if .Loopback}}<p class="warning">The answer goes to an application on this computer. Allow it only if you started it.</p>{{end}}
{{if .AppScheme}}<p class="warning">The answer goes to an app on this device. Allow it only if you started it.</p>{{end}}
<form method="post" action="{{.DecisionPath}}">
<input type="hidden" name="request_id" value="{{.RequestId}}">
<button type="submit" name="decision" value="allow">Allow</button>
<button type="submit" name="decision" value="deny">Deny</button>
</form>
</main>
</body>
</html>
`))

var messageTemplate = template.Must(template.New("message").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title>
<style>` + style + `</style>
</head>
<body>
<main>
<h1>{{.Title}}</h1>
<p>{{.Detail}}</p>
</main>
</body>
</html>
`))

// Consent is what the consent page shows.
type Consent struct {
	ClientName string
	ClientId   string
	// SelfRegistered is a client whose name nothing vouches for, and whose id is no name.
	SelfRegistered bool
	RedirectUri    string
	ResourceName   string
	ResourceUrl    string
	Scope          string
	RequestId      string
	DecisionPath   string
}

// RenderConsent is the consent page, with the headers it is served with: a form allowed to go to
// the server and on to the client's redirect origin, and nothing else allowed at all.
func RenderConsent(consent *Consent) ([]byte, []*muxResponse.HeaderEntry, error) {
	redirectUrl, err := url.Parse(consent.RedirectUri)
	if err != nil {
		return nil, nil, altshiftErrors.NewWithTrace(fmt.Errorf("url parse (redirect uri): %w", err), consent.RedirectUri)
	}
	loopback := client.IsLoopback(redirectUrl)
	// An app's own scheme (RFC 8252 section 7.1) names no host: whatever app on the device claims
	// the scheme is sent the answer.
	appScheme := redirectUrl.Host == "" && redirectUrl.Scheme != "http" && redirectUrl.Scheme != "https"

	sentTo := redirectUrl.Host
	if appScheme {
		sentTo = "an app on this device, by its link " + redirectUrl.Scheme + ":"
	}
	data := struct {
		*Consent
		RedirectHost string
		Loopback     bool
		AppScheme    bool
	}{Consent: consent, RedirectHost: sentTo, Loopback: loopback, AppScheme: appScheme}

	var buffer bytes.Buffer
	if err := consentTemplate.Execute(&buffer, data); err != nil {
		return nil, nil, altshiftErrors.NewWithTrace(fmt.Errorf("consent template execute: %w", err))
	}

	// The form's answer redirects on to the client, and form-action is held to the redirect as well
	// as to the form's own target.
	origin := &url.URL{Scheme: redirectUrl.Scheme, Host: redirectUrl.Host}
	if loopback {
		origin.Host = net.JoinHostPort(redirectUrl.Hostname(), "*")
	}

	return buffer.Bytes(), Headers("'self' " + origin.String()), nil
}

// RenderMessage is a page saying why a request was refused.
func RenderMessage(title string, detail string) ([]byte, []*muxResponse.HeaderEntry, error) {
	var buffer bytes.Buffer
	if err := messageTemplate.Execute(&buffer, struct{ Title, Detail string }{title, detail}); err != nil {
		return nil, nil, altshiftErrors.NewWithTrace(fmt.Errorf("message template execute: %w", err))
	}
	return buffer.Bytes(), Headers("'none'"), nil
}

// Headers are a page's: not cached, not framed, loading nothing, its forms going only to
// formAction.
func Headers(formAction string) []*muxResponse.HeaderEntry {
	policy := strings.Join([]string{
		"default-src 'none'",
		"style-src 'unsafe-inline'",
		"form-action " + formAction,
		"frame-ancestors 'none'",
		"base-uri 'none'",
	}, "; ")

	return []*muxResponse.HeaderEntry{
		{Name: "Content-Type", Value: "text/html; charset=utf-8"},
		{Name: "Cache-Control", Value: "no-store", Overwrite: true},
		{Name: "Content-Security-Policy", Value: policy, Overwrite: true},
		{Name: "X-Frame-Options", Value: "DENY", Overwrite: true},
	}
}
