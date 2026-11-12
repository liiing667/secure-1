package secure

import (
	"net"
	"net/http"
	"strings"
)

// TrustProxyFunc is a custom function type that determines whether the request
// originates from a trusted reverse proxy. It receives the original request so
// the decision can be based on r.RemoteAddr or any other request property.
type TrustProxyFunc func(r *http.Request) bool

// isTrustedProxy reports whether the request's immediate peer (r.RemoteAddr) is
// allowed to supply proxy headers. When neither TrustedProxies nor
// TrustProxyFunc is configured, proxy headers retain their legacy behavior and
// are trusted for every request.
func (s *Secure) isTrustedProxy(r *http.Request) bool {
	if len(s.opt.TrustedProxies) == 0 && s.opt.TrustProxyFunc == nil {
		return true
	}

	if s.opt.TrustProxyFunc != nil && s.opt.TrustProxyFunc(r) {
		return true
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// RemoteAddr carries no port (for example "127.0.0.1" or "::1").
		host = r.RemoteAddr
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	for _, network := range s.trustedProxyNetworks {
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// proxyHost resolves the effective request host from the configured host proxy
// headers. Headers from untrusted peers, and malformed or conflicting header
// values, are ignored: the real r.Host is used instead (fail closed).
func (s *Secure) proxyHost(r *http.Request, trusted bool) string {
	if !trusted || len(s.opt.HostsProxyHeaders) == 0 {
		return r.Host
	}

	// Legacy mode: no trust boundary is configured, preserve the historical
	// behavior of trusting the first matching header for every request.
	if !s.proxyTrustConfigured() {
		for _, header := range s.opt.HostsProxyHeaders {
			if h := r.Header.Get(header); h != "" {
				return h
			}
		}

		return r.Host
	}

	for _, header := range s.opt.HostsProxyHeaders {
		values := r.Header.Values(header)
		if len(values) == 0 || (len(values) == 1 && values[0] == "") {
			continue
		}

		// Multiple header lines, a comma-separated forwarding list, embedded
		// whitespace, or a syntactically invalid host are all ambiguous. Never
		// guess: fall back to the host from the actual request line.
		if len(values) != 1 ||
			strings.ContainsAny(values[0], ", \t") ||
			!isValidHost(values[0]) {
			return r.Host
		}

		return values[0]
	}

	return r.Host
}

// proxySSL reports whether a trusted proxy header establishes that the original
// connection used HTTPS. Untrusted peers, malformed and conflicting headers
// never upgrade the connection state (fail closed).
func (s *Secure) proxySSL(r *http.Request, trusted bool) bool {
	if !trusted {
		return false
	}

	// Legacy mode: preserve the historical single-value comparison.
	if !s.proxyTrustConfigured() {
		for header, expected := range s.opt.SSLProxyHeaders {
			if r.Header.Get(header) == expected {
				return true
			}
		}

		return false
	}

	for header, expected := range s.opt.SSLProxyHeaders {
		values := r.Header.Values(header)
		if len(values) == 0 {
			continue
		}

		if len(values) != 1 || strings.TrimSpace(values[0]) != expected {
			return false
		}

		return true
	}

	return false
}

// proxyTrustConfigured reports whether an explicit trust boundary (CIDR ranges
// or a callback) is configured.
func (s *Secure) proxyTrustConfigured() bool {
	return len(s.opt.TrustedProxies) > 0 || s.opt.TrustProxyFunc != nil
}

// isValidHost reports whether host is a syntactically valid host name, IP
// literal, or host:port authority.
func isValidHost(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}

	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	// Bracket-wrapped IPv6 literal such as "[2001:db8::1]".
	if strings.HasPrefix(host, "[") {
		if !strings.HasSuffix(host, "]") {
			return false
		}

		host = host[1 : len(host)-1]
	}

	if ip := net.ParseIP(host); ip != nil {
		return true
	}

	// RFC 3986 reg-name. Underscores are tolerated because they occur in
	// real-world internal host names, even though they are not valid DNS labels.
	for _, char := range host {
		switch {
		case char >= 'a' && char <= 'z':
		case char >= 'A' && char <= 'Z':
		case char >= '0' && char <= '9':
		case char == '.' || char == '-' || char == '_':
		default:
			return false
		}
	}

	return true
}
