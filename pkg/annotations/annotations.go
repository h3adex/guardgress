package annotations

import (
	"github.com/h3adex/guardgress/pkg/models"
	log "github.com/sirupsen/logrus"
	"strings"
)

const (
	Ja3Blacklist            = "guardgress/ja3-blacklist"
	Ja4Blacklist            = "guardgress/ja4-blacklist"
	UserAgentBlacklist      = "guardgress/user-agent-blacklist"
	AddTLSFingerprintHeader = "guardgress/add-tls-fingerprint-header"
	ForceSSLRedirect        = "guardgress/force-ssl-redirect"
	LimitIpWhitelist        = "guardgress/limit-ip-whitelist"
	LimitPathWhitelist      = "guardgress/limit-path-whitelist"
	LimitRedisStore         = "guardgress/limit-redis-store-url"
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

func IsUserAgentInBlacklist(annotations map[string]string, userAgent string) bool {
	if userAgentBlacklist, ok := annotations[UserAgentBlacklist]; ok {
		for _, ua := range strings.Split(userAgentBlacklist, ",") {
			if ua == userAgent {
				log.Errorf("User agent got blacklisted: %s", userAgent)
				return true
			}
		}
	}
	return false
}

func IsTlsFingerprintBlacklisted(annotations map[string]string, parsedClientHello models.ClientHelloParsed) bool {
	blacklistKeys := []string{Ja3Blacklist, Ja4Blacklist}

	for _, key := range blacklistKeys {
		tlsBlacklist, ok := annotations[key]
		if !ok {
			continue
		}

		for _, tlsHash := range strings.Split(tlsBlacklist, ",") {
			switch key {
			case Ja3Blacklist:
				if tlsHash == parsedClientHello.Ja3 || tlsHash == parsedClientHello.Ja3n {
					log.Errorf("Ja3 fingerprint got blacklisted: %s", parsedClientHello.Ja3)
					return true
				}
			case Ja4Blacklist:
				if tlsHash == parsedClientHello.Ja4 || tlsHash == parsedClientHello.Ja4h {
					log.Errorf("Ja4 fingerprint got blacklisted: %s", parsedClientHello.Ja4)
					return true
				}
			}
		}
	}

	return false
}

func IsPathWhiteListed(annotations map[string]string, path string) bool {
	pathWhitelist, ok := annotations[LimitPathWhitelist]
	if !ok {
		return false
	}

	for _, parsedPath := range strings.Split(pathWhitelist, ",") {
		if strings.HasPrefix(path, parsedPath) {
			return true
		}
	}

	return false
}

func IsIpWhitelisted(annotations map[string]string, ip string) bool {
	ipWhitelist, ok := annotations[LimitIpWhitelist]
	if !ok {
		return false
	}

	for _, parsedIP := range strings.Split(ipWhitelist, ",") {
		if parsedIP == ip {
			return true
		}
	}

	return false
}

func IsTLSFingerprintHeaderRequested(annotations map[string]string) bool {
	val, exists := annotations[AddTLSFingerprintHeader]
	return exists && val == "true"
}
