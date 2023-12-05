package annotations

import (
	"github.com/h3adex/guardgress/pkg/models"
	"strings"
)

const (
	Ja3Blacklist       = "guardgress/ja3-blacklist"
	Ja4Blacklist       = "guardgress/ja4-blacklist"
	UserAgentBlacklist = "guardgress/user-agent-blacklist"
	AddJa3HeaderKey    = "guardgress/add-ja3-header"
	AddJa4HeaderKey    = "guardgress/add-ja4-header"
	LimitWhitelist     = "guardgress/limit-ip-whitelist"
	// LimitPeriod uses the simplified format "<limit>-<period>"", with the given
	// periods:
	//
	// * "S": second
	// * "M": minute
	// * "H": hour
	// * "D": day
	//
	// Examples:
	//
	// * 5 reqs/second: "5-S"
	// * 10 reqs/minute: "10-M"
	// * 1000 reqs/hour: "1000-H"
	// * 2000 reqs/day: "2000-D"
	LimitPeriod = "guardgress/limit-period"
)

func isHeaderEnabled(annotations map[string]string, key string) bool {
	val, exists := annotations[key]
	return exists && val == "true"
}

func IsUserAgentBlacklisted(annotations map[string]string, userAgent string) bool {
	if userAgentBlacklist, ok := annotations[UserAgentBlacklist]; ok {
		for _, ua := range strings.Split(userAgentBlacklist, ",") {
			if ua == userAgent {
				return true
			}
		}
	}

	return false
}

func IsTlsFingerprintBlacklisted(
	annotations map[string]string,
	parsedClientHello models.ClientHelloParsed,
) bool {
	blacklistKeys := []string{Ja3Blacklist, Ja4Blacklist}

	for _, key := range blacklistKeys {
		if tlsBlacklist, ok := annotations[key]; ok {
			for _, tlsHash := range strings.Split(tlsBlacklist, ",") {
				if key == Ja3Blacklist {
					if tlsHash == parsedClientHello.Ja3 || tlsHash == parsedClientHello.Ja3n {
						return true
					}
				}

				if key == Ja4Blacklist {
					if tlsHash == parsedClientHello.Ja4 || tlsHash == parsedClientHello.Ja4h {
						return true
					}
				}
			}
		}
	}

	return false
}

func IsIpWhitelisted(annotations map[string]string, ip string) bool {
	if whitelist, ok := annotations[LimitWhitelist]; ok {
		for _, ipWhitelist := range strings.Split(whitelist, ",") {
			if ipWhitelist == ip {
				return true
			}
		}
	}

	return false
}

func AddJa3Header(annotations map[string]string) bool {
	return isHeaderEnabled(annotations, AddJa3HeaderKey)
}

func AddJa4Header(annotations map[string]string) bool {
	return isHeaderEnabled(annotations, AddJa4HeaderKey)
}
