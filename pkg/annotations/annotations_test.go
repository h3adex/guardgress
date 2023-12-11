package annotations

import (
	"github.com/h3adex/guardgress/pkg/models"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestAnnotations(t *testing.T) {
	mockAnnotations := map[string]string{
		"guardgress/add-tls-fingerprint-header": "true",
		"guardgress/user-agent-blacklist":       "curl/7.64.1,curl/7.64.2",
		"guardgress/ja3-blacklist":              "d41d8cd98f00b204e9800998ecf8427a",
		"guardgress/ja4-blacklist":              "t13d1715h2_5b57614c22b0_93c746dc12af",
		"guardgress/limit-ip-whitelist":         "127.0.0.1,127.0.0.2",
		"guardgress/limit-path-whitelist":       "/shop/products/,/.well-known",
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

	t.Run("test user agent blacklisting", func(t *testing.T) {
		assert.True(
			t,
			IsUserAgentInBlacklist(
				mockAnnotations,
				"curl/7.64.1",
			),
		)

		assert.False(
			t,
			IsUserAgentInBlacklist(
				mockAnnotations,
				"curl/7.64.1_false",
			),
		)
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

	t.Run("test add tls fingerprint header", func(t *testing.T) {
		assert.True(t, IsTLSFingerprintHeaderRequested(mockAnnotations))
	})
}
