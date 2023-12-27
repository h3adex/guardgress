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

func TestIsIpWhitelisted(t *testing.T) {
	t.Run("test ip whitelisting", func(t *testing.T) {
		mockAnnotations := map[string]string{
			"guardgress/limit-ip-whitelist": "127.0.0.1,127.0.0.2",
		}

		cases := map[string]bool{
			"127.0.0.1":       true,
			"127.0.0.2":       true,
			"127.0.0.2_false": false,
		}

		for key, val := range cases {
			assert.Equal(t, val, IsIpWhitelisted(mockAnnotations, key))
		}
	})

	t.Run("test path whitelisting", func(t *testing.T) {
		mockAnnotations := map[string]string{
			"guardgress/limit-path-whitelist": "/shop/products/,/.well-known",
		}

		cases := map[string]bool{
			"/shop":                  false,
			"/shop/products/abc":     true,
			"/shop/products/def/buy": true,
			"/.well-known":           true,
			"/.well-known/foo":       true,
			"/test/healthz":          false,
		}

		for key, val := range cases {
			assert.Equal(t, val, IsPathWhiteListed(mockAnnotations, key))
		}
	})
}

func TestAddTlsFingerprintHeader(t *testing.T) {
	mockAnnotations := map[string]string{
		"guardgress/add-tls-fingerprint-header": "true",
	}

	t.Run("test add tls fingerprint header", func(t *testing.T) {
		assert.True(t, IsTLSFingerprintHeaderRequested(mockAnnotations))
	})
}

func TestTLSFingerprintWhiteBlacklistAnnotations(t *testing.T) {
	t.Run("test tls fingerprint blacklist", func(t *testing.T) {
		mockAnnotations := map[string]string{
			"guardgress/tls-fingerprint-blacklist": "t13d1715h2_5b57614c22b0_93c746dc12af,d41d8cd98f00b204e9800998ecf8427a",
		}
		cases := map[string]bool{
			"t13d1715h2_5b57614c22b0_93c746dc12af":             false,
			"d41d8cd98f00b204e9800998ecf8427a":                 false,
			"d41d8cd98f00b204e9800998ecf8427a_should_work":     true,
			"t13d1715h2_5b57614c22b0_93c746dc12af_should_work": true,
		}

		for key, val := range cases {
			ok, _ := IsTLSFingerprintAllowed(mockAnnotations, models.ParsedClientHello{
				Ja3:  key,
				Ja3H: key,
				Ja3n: key,
				Ja4:  key,
				Ja4h: key,
			})
			assert.Equal(t, val, ok)
		}
	})

	t.Run("test tls fingerprint whitelist", func(t *testing.T) {
		mockAnnotations := map[string]string{
			"guardgress/tls-fingerprint-whitelist": "t13d1715h2_5b57614c22b0_93c746dc12af,d41d8cd98f00b204e9800998ecf8427a",
		}
		cases := map[string]bool{
			"t13d1715h2_5b57614c22b0_93c746dc12af":                 true,
			"d41d8cd98f00b204e9800998ecf8427a":                     true,
			"d41d8cd98f00b204e9800998ecf8427a_should_not_work":     false,
			"t13d1715h2_5b57614c22b0_93c746dc12af_should_not_work": false,
		}

		for key, val := range cases {
			ok, _ := IsTLSFingerprintAllowed(mockAnnotations, models.ParsedClientHello{
				Ja3:  key,
				Ja3H: key,
				Ja3n: key,
				Ja4:  key,
				Ja4h: key,
			})
			assert.Equal(t, val, ok)
		}
	})

	t.Run("test tls fingerprint whitelist/blacklist combined", func(t *testing.T) {
		mockAnnotations := map[string]string{
			"guardgress/tls-fingerprint-whitelist": "d41d8cd98f00b204e9800998ecf8427a",
			"guardgress/tls-fingerprint-blacklist": "t13d1715h2_5b57614c22b0_93c746dc12af,d41d8cd98f00b204e9800998ecf8427a",
		}
		cases := map[string]bool{
			"d41d8cd98f00b204e9800998ecf8427a":                     true,
			"t13d1715h2_5b57614c22b0_93c746dc12af":                 false,
			"d41d8cd98f00b204e9800998ecf8427a_should_not_work":     false,
			"t13d1715h2_5b57614c22b0_93c746dc12af_should_not_work": false,
		}

		for key, val := range cases {
			ok, _ := IsTLSFingerprintAllowed(mockAnnotations, models.ParsedClientHello{
				Ja3:  key,
				Ja3H: key,
				Ja3n: key,
				Ja4:  key,
				Ja4h: key,
			})
			assert.Equal(t, val, ok)
		}
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
