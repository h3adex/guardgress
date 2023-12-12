package annotations

import (
	"github.com/h3adex/guardgress/pkg/models"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"testing"
)

func init() {
	log.SetLevel(log.DebugLevel)
}

func TestAnnotations(t *testing.T) {
	mockAnnotations := map[string]string{
		"guardgress/add-tls-fingerprint-header": "true",
		// ja4,ja3
		"guardgress/tls-fingerprint-blacklist": "t13d1715h2_5b57614c22b0_93c746dc12af,d41d8cd98f00b204e9800998ecf8427a",
		"guardgress/limit-ip-whitelist":        "127.0.0.1,127.0.0.2",
		"guardgress/limit-path-whitelist":      "/shop/products/,/.well-known",
	}

	t.Run("test tls fingerprint blacklisting", func(t *testing.T) {
		assert.True(
			t,
			IsTlsFingerprintBlacklisted(
				mockAnnotations,
				models.ClientHelloParsed{Ja3: "d41d8cd98f00b204e9800998ecf8427a"},
			),
		)

		assert.False(
			t,
			IsTlsFingerprintBlacklisted(
				mockAnnotations,
				models.ClientHelloParsed{Ja3: "d41d8cd98f00b204e9800998ecf8427a_false"},
			),
		)

		assert.True(
			t,
			IsTlsFingerprintBlacklisted(
				mockAnnotations,
				models.ClientHelloParsed{Ja4: "t13d1715h2_5b57614c22b0_93c746dc12af"},
			),
		)

		assert.False(
			t,
			IsTlsFingerprintBlacklisted(
				mockAnnotations,
				models.ClientHelloParsed{Ja4: "t13d1715h2_5b57614c22b0_93c746dc12af_false"},
			),
		)
	})

	t.Run("test add tls fingerprint header", func(t *testing.T) {
		assert.True(t, IsTLSFingerprintHeaderRequested(mockAnnotations))
	})

	t.Run("test ip whitelisting", func(t *testing.T) {
		assert.True(
			t,
			IsIpWhitelisted(
				mockAnnotations,
				"127.0.0.1",
			),
		)

		assert.True(
			t,
			IsIpWhitelisted(
				mockAnnotations,
				"127.0.0.2",
			),
		)

		assert.False(
			t,
			IsIpWhitelisted(
				mockAnnotations,
				"127.0.0.1_false",
			),
		)

		assert.False(
			t,
			IsPathWhiteListed(mockAnnotations, "/shop"),
		)

		assert.True(
			t,
			IsPathWhiteListed(mockAnnotations, "/shop/products/abc"),
		)

		assert.True(
			t,
			IsPathWhiteListed(mockAnnotations, "/shop/products/def/buy"),
		)

		assert.True(
			t,
			IsPathWhiteListed(mockAnnotations, "/.well-known"),
		)

		assert.True(
			t,
			IsPathWhiteListed(mockAnnotations, "/.well-known/foo"),
		)

		assert.False(
			t,
			IsPathWhiteListed(mockAnnotations, "/test/healthz"),
		)
	})
}

func TestUserAgentWhiteBlackListAnnotations(t *testing.T) {
	t.Run("test user-agent blacklist curl-ua", func(t *testing.T) {
		mockAnnotations := map[string]string{
			"guardgress/user-agent-blacklist": "curl/7.64.3,curl/7.65.*",
		}
		cases := map[string]bool{
			"curl/7.64.3": false,
			"curl/7.64.4": true,
			"curl/7.65.1": false,
			"curl/7.65.2": false,
			"curl/7.66.2": true,
		}

		for key, val := range cases {
			assert.Equal(t, val, IsUserAgentAllowed(mockAnnotations, key))
		}
	})

	t.Run("test user-agent blacklist browser-ua", func(t *testing.T) {
		mockAnnotations := map[string]string{
			"guardgress/user-agent-blacklist": "Chrome/120.0.0.0,Safari/538.36",
		}
		cases := map[string]bool{
			// blocked
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36": false,
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/538.36": false,
			// not blocked
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.37": true,
		}

		for key, val := range cases {
			assert.Equal(t, val, IsUserAgentAllowed(mockAnnotations, key))
		}
	})

	t.Run("test user-agent whitelist curl-ua", func(t *testing.T) {
		mockAnnotations := map[string]string{
			"guardgress/user-agent-whitelist": "curl/7.64.3,curl/7.65.*",
		}
		cases := map[string]bool{
			"curl/7.64.3": true,
			"curl/7.64.4": false,
			"curl/7.65.1": true,
			"curl/7.65.2": true,
			"curl/7.66.2": false,
		}

		for key, val := range cases {
			assert.Equal(t, val, IsUserAgentAllowed(mockAnnotations, key))
		}
	})

	t.Run("test user-agent whitelist browser-ua", func(t *testing.T) {
		mockAnnotations := map[string]string{
			"guardgress/user-agent-whitelist": "Chrome/120.0.0.0,Safari/538.36",
		}
		cases := map[string]bool{
			// not blocked
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36": true,
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/538.36": true,
			// blocked
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.37": false,
		}

		for key, val := range cases {
			assert.Equal(t, val, IsUserAgentAllowed(mockAnnotations, key))
		}
	})

	t.Run("test user-agent whitelist/blacklist combined curl-ua", func(t *testing.T) {
		mockAnnotations := map[string]string{
			"guardgress/user-agent-whitelist": "curl/7.65.*",
			"guardgress/user-agent-blacklist": "curl/7.64.3,curl/7.65.*",
		}
		cases := map[string]bool{
			"curl/7.64.3": false,
			"curl/7.64.4": false,
			"curl/7.65.1": true,
			"curl/7.65.2": true,
			"curl/7.66.2": false,
		}

		for key, val := range cases {
			assert.Equal(t, val, IsUserAgentAllowed(mockAnnotations, key))
		}
	})
}
