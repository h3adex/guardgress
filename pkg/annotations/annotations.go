package annotations

import (
	"github.com/h3adex/guardgress/pkg/algorithms"
	"github.com/h3adex/guardgress/pkg/models"
	log "github.com/sirupsen/logrus"
	"regexp"
	"strings"
)

const (
	UserAgentBlacklist      = "guardgress/user-agent-blacklist"
	TLSFingerprintBlackList = "guardgress/tls-fingerprint-blacklist"
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
		for _, uaPattern := range strings.Split(userAgentBlacklist, ",") {
			matched, err := regexp.MatchString(uaPattern, userAgent)
			if err != nil {
				log.Errorf("Error matching user agent: %s", err)
				continue
			}
			if matched {
				log.Errorf("User agent got blacklisted: %s", userAgent)
				return true
			}
		}
	}
	return false
}

func IsTlsFingerprintBlacklisted(annotations map[string]string, parsedClientHello models.ClientHelloParsed) bool {
	tlsBlacklist, ok := annotations[TLSFingerprintBlackList]
	if !ok {
		return false
	}

	for _, tlsBlacklistValue := range strings.Split(tlsBlacklist, ",") {
		if tlsBlacklistValue == parsedClientHello.Ja3 || tlsBlacklistValue == parsedClientHello.Ja3n || tlsBlacklistValue == algorithms.Ja3Digest(parsedClientHello.Ja3) {
			log.Errorf("Ja3 fingerprint got blacklisted: %s", parsedClientHello.Ja3)
			return true
		}
		if tlsBlacklistValue == parsedClientHello.Ja4 || tlsBlacklistValue == parsedClientHello.Ja4h {
			log.Errorf("Ja4 fingerprint got blacklisted: %s", parsedClientHello.Ja4)
			return true
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
