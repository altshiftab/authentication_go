package redirect_scheme

import (
	"net/url"
	"testing"
)

func TestAllowed(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name              string
		target            string
		allowLoopbackHttp bool
		want              bool
	}{
		{name: "https", target: "https://app.example.com/back", want: true},
		{name: "https with loopback http allowed", target: "https://app.example.com/back", allowLoopbackHttp: true, want: true},
		{name: "https, whatever the case it was written in", target: "HTTPS://app.example.com/back", want: true},
		{name: "plain http to a public host", target: "http://app.example.com/back"},
		{name: "plain http to a public host, loopback http allowed", target: "http://app.example.com/back", allowLoopbackHttp: true},
		{name: "plain http to localhost where it is allowed", target: "http://localhost:8080/back", allowLoopbackHttp: true, want: true},
		{name: "plain http to a name under localhost where it is allowed", target: "http://app.localhost/back", allowLoopbackHttp: true, want: true},
		{name: "plain http to a loopback address where it is allowed", target: "http://127.0.0.1:8080/back", allowLoopbackHttp: true, want: true},
		{name: "plain http to the ipv6 loopback where it is allowed", target: "http://[::1]:8080/back", allowLoopbackHttp: true, want: true},
		{name: "plain http to localhost where it is not allowed", target: "http://localhost:8080/back"},
		{name: "a name that only begins with localhost", target: "http://localhost.example.com/back", allowLoopbackHttp: true},
		{name: "a script with an authority", target: "javascript://app.example.com/%0aalert(1)", allowLoopbackHttp: true},
		{name: "a script without one", target: "javascript:alert(1)"},
		{name: "an android intent", target: "intent://app.example.com/#Intent;scheme=https;end"},
		{name: "an app's own scheme", target: "com.example.app://app.example.com/back"},
		{name: "a data url", target: "data://app.example.com/,x"},
		{name: "a websocket", target: "wss://app.example.com/socket"},
		{name: "no scheme at all", target: "//app.example.com/back"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			target, err := url.Parse(testCase.target)
			if err != nil {
				t.Fatalf("%s: url parse: %v", testCase.name, err)
			}

			if got := Allowed(target, testCase.allowLoopbackHttp); got != testCase.want {
				t.Errorf("%s: allowed %t, want %t", testCase.name, got, testCase.want)
			}
		})
	}

	t.Run("no target", func(t *testing.T) {
		t.Parallel()

		if Allowed(nil, true) {
			t.Error("no target is allowed")
		}
	})
}
