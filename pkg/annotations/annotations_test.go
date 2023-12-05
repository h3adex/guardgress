package annotations

import (
	"github.com/h3adex/guardgress/pkg/models"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestAnnotations(t *testing.T) {
	mockAnnotations := map[string]string{
		"guardgress/add-ja3-header":       "true",
		"guardgress/add-ja4-header":       "true",
		"guardgress/user-agent-blacklist": "curl/7.64.1,curl/7.64.2",
		"guardgress/ja3-blacklist":        "d41d8cd98f00b204e9800998ecf8427a",
		"guardgress/ja4-blacklist":        "t13d1715h2_5b57614c22b0_93c746dc12af",
		"guardgress/limit-ip-whitelist":   "127.0.0.1,127.0.0.2",
	}

	assert.Equal(
		t,
		IsTlsFingerprintBlacklisted(
			mockAnnotations,
			models.ClientHelloParsed{Ja3: "d41d8cd98f00b204e9800998ecf8427a"},
		),
		true,
	)

	assert.Equal(
		t,
		IsTlsFingerprintBlacklisted(
			mockAnnotations,
			models.ClientHelloParsed{Ja3: "d41d8cd98f00b204e9800998ecf8427a_false"},
		),
		false,
	)

	assert.Equal(
		t,
		IsTlsFingerprintBlacklisted(
			mockAnnotations,
			models.ClientHelloParsed{Ja4: "t13d1715h2_5b57614c22b0_93c746dc12af"},
		),
		true,
	)

	assert.Equal(
		t,
		IsTlsFingerprintBlacklisted(
			mockAnnotations,
			models.ClientHelloParsed{Ja4: "t13d1715h2_5b57614c22b0_93c746dc12af_false"},
		),
		false,
	)

	assert.Equal(
		t,
		IsUserAgentBlacklisted(
			mockAnnotations,
			"curl/7.64.1",
		),
		true,
	)

	assert.Equal(
		t,
		IsUserAgentBlacklisted(
			mockAnnotations,
			"curl/7.64.1_false",
		),
		false,
	)

	assert.Equal(
		t,
		IsIpWhitelisted(
			mockAnnotations,
			"127.0.0.1",
		),
		true,
	)

	assert.Equal(
		t,
		IsIpWhitelisted(
			mockAnnotations,
			"127.0.0.2",
		),
		true,
	)

	assert.Equal(
		t,
		IsIpWhitelisted(
			mockAnnotations,
			"127.0.0.1_false",
		),
		false,
	)

	assert.Equal(t, AddJa3Header(mockAnnotations), true)
}
