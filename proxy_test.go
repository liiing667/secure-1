package secure

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

const (
	trustedIPv4   = "10.1.2.3:51234"
	untrustedIPv4 = "203.0.113.9:51234"
	trustedIPv6   = "[2001:db8::1]:51234"
	untrustedIPv6 = "[2001:db9::2]:51234"
)

func proxyOptions() Options {
	return Options{
		AllowedHosts:      []string{"www.example.com"},
		HostsProxyHeaders: []string{"X-Forwarded-Host"},
		SSLRedirect:       true,
		SSLProxyHeaders:   map[string]string{"X-Forwarded-Proto": "https"},
		STSSeconds:        31536000,
	}
}

func forgeRequest(remoteAddr string) *http.Request {
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "/foo", nil)
	req.Host = "www.example.com"
	req.RemoteAddr = remoteAddr
	req.Header.Set("X-Forwarded-Host", "evil.attacker.com")
	req.Header.Set("X-Forwarded-Proto", "https")

	return req
}

// An untrusted direct client must not be able to use proxy headers to spoof the
// host or pretend the connection is HTTPS.
func TestUntrustedPeerHeadersIgnored(t *testing.T) {
	options := proxyOptions()
	options.TrustedProxies = []string{"10.0.0.0/8", "2001:db8::/32"}
	s := New(options)

	for _, remoteAddr := range []string{untrustedIPv4, untrustedIPv6} {
		res := httptest.NewRecorder()
		req := forgeRequest(remoteAddr)
		s.Handler(myHandler).ServeHTTP(res, req)

		expect(t, res.Code, http.StatusMovedPermanently)
		expect(t, res.Header().Get("Location"), "https://www.example.com/foo")
		expect(t, res.Header().Get(stsHeader), "")
	}
}

// A trusted proxy's headers must be honored for both IPv4 and IPv6 peers.
func TestTrustedPeerHeadersHonored(t *testing.T) {
	options := proxyOptions()
	options.TrustedProxies = []string{"10.0.0.0/8", "2001:db8::/32"}
	s := New(options)

	for _, remoteAddr := range []string{trustedIPv4, trustedIPv6} {
		res := httptest.NewRecorder()
		req := forgeRequest(remoteAddr)
		req.Header.Set("X-Forwarded-Host", "www.example.com")
		s.Handler(myHandler).ServeHTTP(res, req)

		expect(t, res.Code, http.StatusOK)
		expect(t, res.Header().Get(stsHeader), "max-age=31536000")
	}
}

// Without any trust boundary configured, the legacy behavior trusts proxy
// headers for every request so existing deployments keep working.
func TestLegacyModeStillTrustsProxyHeaders(t *testing.T) {
	s := New(proxyOptions())

	req := forgeRequest(untrustedIPv4)
	req.Header.Set("X-Forwarded-Host", "www.example.com")
	res := httptest.NewRecorder()
	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get(stsHeader), "max-age=31536000")
}

// A forged forwarded host must not bypass the AllowedHosts check for
// untrusted peers; the real host is evaluated instead.
func TestUntrustedPeerCannotBypassAllowedHosts(t *testing.T) {
	options := proxyOptions()
	options.TrustedProxies = []string{"10.0.0.0/8"}
	s := New(options)

	req := forgeRequest(untrustedIPv4)
	req.Host = "internal-origin"

	recorder := httptest.NewRecorder()
	s.Handler(myHandler).ServeHTTP(recorder, req)

	expect(t, recorder.Code, http.StatusInternalServerError)
}

// Duplicate or malformed host headers from a trusted proxy are ambiguous and
// must fail closed by falling back to the real r.Host.
func TestTrustedPeerMalformedHostHeadersFailClosed(t *testing.T) {
	options := proxyOptions()
	options.TrustedProxies = []string{"10.0.0.0/8"}
	s := New(options)

	cases := []struct {
		name   string
		values []string
	}{
		{"duplicate lines", []string{"www.example.com", "evil.attacker.com"}},
		{"comma list", []string{"www.example.com, evil.attacker.com"}},
		{"leading space", []string{" www.example.com"}},
		{"invalid characters", []string{"www .example$.com"}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := forgeRequest(trustedIPv4)
			req.Header.Del("X-Forwarded-Host")
			for _, value := range c.values {
				req.Header.Add("X-Forwarded-Host", value)
			}

			res := httptest.NewRecorder()
			s.Handler(myHandler).ServeHTTP(res, req)

			// The real host (www.example.com) is used instead of the forged
			// value, while the valid proto header still marks HTTPS: the
			// request succeeds and carries the STS header.
			expect(t, res.Code, http.StatusOK)
			expect(t, res.Header().Get(stsHeader), "max-age=31536000")
		})
	}
}

// Duplicate or conflicting proto headers must not upgrade an HTTP connection.
func TestTrustedPeerConflictingProtoHeadersFailClosed(t *testing.T) {
	options := proxyOptions()
	options.TrustedProxies = []string{"10.0.0.0/8"}
	s := New(options)

	cases := []struct {
		name   string
		values []string
	}{
		{"duplicate lines", []string{"https", "http"}},
		{"comma list", []string{"https,http"}},
		{"embedded whitespace", []string{"ht tps"}},
		{"unexpected value", []string{"superman"}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := forgeRequest(trustedIPv4)
			req.Header.Set("X-Forwarded-Host", "www.example.com")
			req.Header.Del("X-Forwarded-Proto")
			for _, value := range c.values {
				req.Header.Add("X-Forwarded-Proto", value)
			}

			res := httptest.NewRecorder()
			s.Handler(myHandler).ServeHTTP(res, req)

			expect(t, res.Code, http.StatusMovedPermanently)
			expect(t, res.Header().Get("Location"), "https://www.example.com/foo")
			expect(t, res.Header().Get(stsHeader), "")
		})
	}
}

// HostsProxyHeaders are inspected in order: the first present header wins, but
// a malformed value in it still fails closed instead of being trusted.
func TestTrustedPeerOrderedHostHeadersFailClosed(t *testing.T) {
	options := proxyOptions()
	options.HostsProxyHeaders = []string{"X-Forwarded-Host", "X-Proxy-Host"}
	options.TrustedProxies = []string{"10.0.0.0/8"}
	s := New(options)

	req := forgeRequest(trustedIPv4)
	req.Header.Set("X-Proxy-Host", "evil.attacker.com")

	res := httptest.NewRecorder()
	s.Handler(myHandler).ServeHTTP(res, req)

	// The first configured header is a single valid attacker host, which is
	// rejected by AllowedHosts via the bad host handler.
	expect(t, res.Code, http.StatusInternalServerError)

	req = forgeRequest(trustedIPv4)
	req.Header.Del("X-Forwarded-Host")
	req.Header.Set("X-Proxy-Host", "www.example.com")

	res = httptest.NewRecorder()
	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
}

// TrustProxyFunc can grant or deny access to proxy headers independently of
// the CIDR configuration.
func TestTrustProxyFunc(t *testing.T) {
	options := proxyOptions()
	options.TrustedProxies = []string{"10.0.0.0/8"}
	options.TrustProxyFunc = func(r *http.Request) bool {
		host, _, err := net.SplitHostPort(r.RemoteAddr)

		return err == nil && host == "198.51.100.7"
	}
	s := New(options)

	// Callback explicitly trusts an address outside the CIDR ranges.
	req := forgeRequest("198.51.100.7:4000")
	req.Header.Set("X-Forwarded-Host", "www.example.com")
	res := httptest.NewRecorder()
	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get(stsHeader), "max-age=31536000")

	// Callback denies and the address is outside the CIDR ranges.
	res = httptest.NewRecorder()
	s.Handler(myHandler).ServeHTTP(res, forgeRequest(untrustedIPv4))

	expect(t, res.Code, http.StatusMovedPermanently)
	expect(t, res.Header().Get("Location"), "https://www.example.com/foo")
}

// A callback alone (without any CIDR) is enough to establish a trust boundary.
func TestTrustProxyFuncOnly(t *testing.T) {
	options := proxyOptions()
	options.TrustProxyFunc = func(r *http.Request) bool { return false }
	s := New(options)

	res := httptest.NewRecorder()
	s.Handler(myHandler).ServeHTTP(res, forgeRequest(trustedIPv4))

	expect(t, res.Code, http.StatusMovedPermanently)
	expect(t, res.Header().Get(stsHeader), "")
}

func TestTrustedProxiesAcceptBareIPs(t *testing.T) {
	options := proxyOptions()
	options.TrustedProxies = []string{"10.1.2.3", "2001:db8::1"}
	s := New(options)

	expect(t, len(s.trustedProxyNetworks), 2)

	for _, remoteAddr := range []string{trustedIPv4, trustedIPv6} {
		req := forgeRequest(remoteAddr)
		req.Header.Set("X-Forwarded-Host", "www.example.com")
		res := httptest.NewRecorder()
		s.Handler(myHandler).ServeHTTP(res, req)

		expect(t, res.Code, http.StatusOK)
	}
}

func TestInvalidTrustedProxiesPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected a panic for an invalid TrustedProxies entry")
		}
	}()

	New(Options{TrustedProxies: []string{"not-a-cidr"}})
}

func TestTrustedProxyMissingRemoteAddrFailsClosed(t *testing.T) {
	options := proxyOptions()
	options.TrustedProxies = []string{"10.0.0.0/8"}
	s := New(options)

	req := forgeRequest("")

	res := httptest.NewRecorder()
	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusMovedPermanently)
	expect(t, res.Header().Get(stsHeader), "")
}

// RemoteAddr may be supplied without a port (for example in some test or
// custom listener setups); the host portion must still be matched.
func TestTrustedProxyRemoteAddrWithoutPort(t *testing.T) {
	options := proxyOptions()
	options.TrustedProxies = []string{"10.0.0.0/8", "2001:db8::/32"}
	s := New(options)

	for _, remoteAddr := range []string{"10.1.2.3", "2001:db8::1"} {
		req := forgeRequest(remoteAddr)
		req.Header.Set("X-Forwarded-Host", "www.example.com")

		res := httptest.NewRecorder()
		s.Handler(myHandler).ServeHTTP(res, req)

		expect(t, res.Code, http.StatusOK)
	}
}

// A malformed host header must never steer an HTTPS redirect to an external
// host: the redirect target is the real r.Host instead.
func TestMalformedHostHeaderRedirectUsesRealHost(t *testing.T) {
	options := Options{
		HostsProxyHeaders: []string{"X-Forwarded-Host"},
		SSLRedirect:       true,
		TrustedProxies:    []string{"10.0.0.0/8"},
	}
	s := New(options)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "/path", nil)
	req.Host = "www.example.com"
	req.RemoteAddr = trustedIPv4
	req.Header.Add("X-Forwarded-Host", "evil.attacker.com")
	req.Header.Add("X-Forwarded-Host", "www.example.com")

	res := httptest.NewRecorder()
	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusMovedPermanently)
	expect(t, res.Header().Get("Location"), "https://www.example.com/path")
}

// The trust decision gates SSL detection directly, independent of redirects.
func TestIsSSLTrustGate(t *testing.T) {
	s := New(Options{
		SSLProxyHeaders: map[string]string{"X-Forwarded-Proto": "https"},
		TrustedProxies:  []string{"10.0.0.0/8"},
	})

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "/foo", nil)
	req.RemoteAddr = untrustedIPv4
	req.Header.Set("X-Forwarded-Proto", "https")

	expect(t, s.isSSL(req, false), false)
	expect(t, s.isSSL(req, true), true)

	req.TLS = &tls.ConnectionState{}
	expect(t, s.isSSL(req, false), true)
}

// End-to-end behavior through real httptest servers on both IP stacks: the
// server-observed RemoteAddr must be the basis of the trust decision.
func TestTrustedProxiesEndToEnd(t *testing.T) {
	cases := []struct {
		name        string
		listen      string
		trusted     string
		untrustedIP string
	}{
		{"IPv4 loopback", "127.0.0.1:0", "127.0.0.1/32", "203.0.113.9"},
		{"IPv6 loopback", "[::1]:0", "::1/128", "2001:db8:dead::2"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			options := proxyOptions()
			options.TrustedProxies = []string{c.trusted}

			handler := New(options).Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("bar"))
			}))
			listener, err := net.Listen("tcp", c.listen)
			if err != nil {
				t.Skipf("listen %s unavailable: %v", c.listen, err)
			}

			server := httptest.NewUnstartedServer(handler)
			server.Listener.Close()
			server.Listener = listener
			server.Start()
			defer server.Close()

			// Trusted peer (the test client connects from loopback).
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL+"/foo", nil)
			req.Header.Set("X-Forwarded-Host", "www.example.com")
			req.Header.Set("X-Forwarded-Proto", "https")

			res, err := http.DefaultTransport.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = res.Body.Close() }()

			expect(t, res.StatusCode, http.StatusOK)
			expect(t, res.Header.Get(stsHeader), "max-age=31536000")

			// Untrusted configuration: loopback is no longer in range, so the
			// forged headers must be ignored and a redirect issued.
			options.TrustedProxies = []string{c.untrustedIP + "/32"}
			if c.name == "IPv6 loopback" {
				options.TrustedProxies = []string{c.untrustedIP + "/128"}
			}

			locked := New(options).Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
			server.Config.Handler = locked

			req, _ = http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL+"/foo", nil)
			req.Host = "www.example.com"
			req.Header.Set("X-Forwarded-Host", "evil.attacker.com")
			req.Header.Set("X-Forwarded-Proto", "https")

			res, err = http.DefaultTransport.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = res.Body.Close() }()

			expect(t, res.StatusCode, http.StatusMovedPermanently)
			expect(t, res.Header.Get("Location"), "https://www.example.com/foo")
			expect(t, res.Header.Get(stsHeader), "")
		})
	}
}
