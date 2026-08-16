package problem_detail_endpoint

import (
	"bytes"
	"fmt"
	"html/template"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/response_error"
	motmedelHttpTypes "github.com/Motmedel/utils_go/pkg/http/types"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail"
	motmedelHttpUtils "github.com/Motmedel/utils_go/pkg/http/utils"
)

// DefaultBackLabel is the default text for the back-to-sign-in control.
const DefaultBackLabel = "Back to sign in"

// htmlMediaRanges lists text/html last so wildcard (*/*) and explicit
// application/problem+json clients still receive a serialized problem document,
// while browsers (which list text/html explicitly and at the highest priority)
// receive HTML.
var htmlMediaRanges = []*motmedelHttpTypes.ServerMediaRange{
	{Type: "application", Subtype: "problem+json"},
	{Type: "application", Subtype: "json"},
	{Type: "application", Subtype: "problem+xml"},
	{Type: "application", Subtype: "xml"},
	{Type: "text", Subtype: "plain"},
	{Type: "text", Subtype: "html"},
}

var problemHtmlTemplate = template.Must(template.New("problem").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title>
</head>
<body>
<main>
<h1>{{.Title}}</h1>
{{if .Detail}}<p>{{.Detail}}</p>{{end}}
{{if .BackUrl}}<p><a href="{{.BackUrl}}">{{.BackLabel}}</a></p>{{end}}
</main>
</body>
</html>
`))

type problemHtmlData struct {
	Title     string
	Detail    string
	BackUrl   string
	BackLabel string
}

// HtmlConverter returns a ProblemDetailConverter that renders an HTML page with a
// link back to backUrl when the client negotiates text/html (i.e. a browser),
// and otherwise serializes the problem detail as problem+json / problem+xml /
// text/plain via the default converter. An empty label uses DefaultBackLabel; an
// empty backUrl omits the link.
//
// Wire it onto a problem endpoint with
// problem_detail_endpoint_config.WithProblemDetailConverter.
func HtmlConverter(backUrl, label string) response_error.ProblemDetailConverterFunction {
	if label == "" {
		label = DefaultBackLabel
	}

	return func(detail *problem_detail.Detail, negotiation *motmedelHttpTypes.ContentNegotiation) ([]byte, string, error) {
		if detail == nil {
			return nil, "", nil
		}

		if negotiation != nil && negotiation.Accept != nil {
			match := motmedelHttpUtils.GetMatchingAccept(negotiation.Accept.GetPriorityOrderedEncodings(), htmlMediaRanges)
			if match != nil && match.GetFullType(true) == "text/html" {
				data := problemHtmlData{Title: detail.Title, Detail: detail.Detail, BackUrl: backUrl, BackLabel: label}

				var buffer bytes.Buffer
				if err := problemHtmlTemplate.Execute(&buffer, data); err != nil {
					return nil, "", motmedelErrors.NewWithTrace(fmt.Errorf("problem html template execute: %w", err))
				}

				return buffer.Bytes(), "text/html; charset=utf-8", nil
			}
		}

		return response_error.ConvertProblemDetail(detail, negotiation)
	}
}
