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

	t.Run("test ip whitelisting no annotation", func(t *testing.T) {
		mockAnnotations := map[string]string{}

		cases := map[string]bool{
			"127.0.0.1":       false,
			"127.0.0.2":       false,
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

	t.Run("test path whitelisting no annotation", func(t *testing.T) {
		mockAnnotations := map[string]string{}

		cases := map[string]bool{
			"/shop": false,
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

		// test ja3 blacklisting
		for key, val := range cases {
			ok, _ := IsTLSFingerprintAllowed(mockAnnotations, models.ParsedClientHello{
				Ja3:  key,
				Ja3H: key,
				Ja3n: key,
				Ja4:  "",
				Ja4h: "",
			})
			assert.Equal(t, val, ok)
		}

		// test ja4 blacklisting
		for key, val := range cases {
			ok, _ := IsTLSFingerprintAllowed(mockAnnotations, models.ParsedClientHello{
				Ja3:  "",
				Ja3H: "",
				Ja3n: "",
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

	t.Run("test user-agent blacklist should not be case-sensitive", func(t *testing.T) {
		mockAnnotations := map[string]string{
			"guardgress/user-agent-blacklist": "Firefox/121.0,chrome/121.0,chrome/122.*",
		}
		cases := map[string]bool{
			"Firefox/121.0":   false,
			"firefox/121.0":   false,
			"Firefox/122.0":   true,
			"chrome/121.0":    false,
			"ChRome/121.0":    false,
			"ChRome/122.1":    false,
			"ChRomE/122.9":    false,
			"ChRomEeee/122.1": true,
		}

		for key, val := range cases {
			assert.Equal(t, val, IsUserAgentAllowed(mockAnnotations, key))
		}
	})
}

func TestWhiteListIPSourceRangeAnnotations(t *testing.T) {
	t.Run("test whitelist ip source range /24", func(t *testing.T) {
		mockAnnotations := map[string]string{
			"guardgress/whitelist-ip-source-range": "192.168.0.0/24,192.169.0.0/24",
		}
		cases := map[string]bool{
			"192.168.0.0":   true,
			"192.168.0.254": true,
			"192.168.1.254": false,
			"192.169.0.0":   true,
			"192.169.0.1":   true,
			"192.169.0.254": true,
			"192.169.1.254": false,
			"192.180.0.0":   false,
			"192.180.1.0":   false,
		}

		for key, val := range cases {
			allowed, err := IsIpAllowed(mockAnnotations, key)
			assert.NoError(t, err)
			assert.Equal(t, val, allowed)
		}
	})

	t.Run("test whitelist ip source range /16", func(t *testing.T) {
		mockAnnotations := map[string]string{
			"guardgress/whitelist-ip-source-range": "192.168.0.0/16,192.169.0.0/16",
		}
		cases := map[string]bool{
			"192.168.0.0":   true,
			"192.168.0.254": true,
			"192.168.1.254": true,
			"192.169.0.0":   true,
			"192.169.0.1":   true,
			"192.169.0.254": true,
			"192.169.1.254": true,
			"192.180.0.0":   false,
			"192.180.1.0":   false,
		}

		for key, val := range cases {
			allowed, err := IsIpAllowed(mockAnnotations, key)
			assert.NoError(t, err)
			assert.Equal(t, val, allowed)
		}
	})

	t.Run("test whitelist ip source range /error", func(t *testing.T) {
		mockAnnotations := map[string]string{
			"guardgress/whitelist-ip-source-range": "192.168.AVC.ABC/8",
		}

		cases := map[string]bool{
			"192.168.0.0": true,
		}

		for key := range cases {
			_, err := IsIpAllowed(mockAnnotations, key)
			assert.Error(t, err)
		}
	})

	t.Run("test whitelist ip source range no annotation set", func(t *testing.T) {
		mockAnnotations := map[string]string{}

		cases := map[string]bool{
			"192.168.0.0": true,
		}

		for key := range cases {
			allowed, err := IsIpAllowed(mockAnnotations, key)
			assert.True(t, allowed)
			assert.NoError(t, err)
		}
	})
}

func TestTlsFingerprintAnnotationExists(t *testing.T) {
	t.Run("test tls fingerprint whitelist annotation exists", func(t *testing.T) {
		mockAnnotations := map[string]string{
			"guardgress/tls-fingerprint-whitelist": "d41d8cd98f00b204e9800998ecf8427a",
		}
		assert.True(t, TlsFingerprintAnnotationExists(mockAnnotations))
	})

	t.Run("test tls fingerprint whitelist annotation exists", func(t *testing.T) {
		mockAnnotations := map[string]string{
			"guardgress/tls-fingerprint-blacklist": "d41d8cd98f00b204e9800998ecf8427a",
		}
		assert.True(t, TlsFingerprintAnnotationExists(mockAnnotations))
	})

	t.Run("test add tls fingerprint header annotation exists", func(t *testing.T) {
		mockAnnotations := map[string]string{
			"guardgress/add-tls-fingerprint-header": "true",
		}
		assert.True(t, TlsFingerprintAnnotationExists(mockAnnotations))
	})

	t.Run("test tls fingerprint annotation does not exist", func(t *testing.T) {
		mockAnnotations := map[string]string{}
		assert.False(t, TlsFingerprintAnnotationExists(mockAnnotations))
	})
}
