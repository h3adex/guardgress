package annotations

import (
	"fmt"
	"github.com/h3adex/guardgress/pkg/algorithms"
	"github.com/h3adex/guardgress/pkg/models"
	log "github.com/sirupsen/logrus"
	"github.com/yl2chen/cidranger"
	"net"
	"regexp"
	"strings"
)

const (
	UserAgentWhitelist      = "guardgress/user-agent-whitelist"
	UserAgentBlacklist      = "guardgress/user-agent-blacklist"
	TLSFingerprintWhitelist = "guardgress/tls-fingerprint-whitelist"
	TLSFingerprintBlackList = "guardgress/tls-fingerprint-blacklist"
	AddTLSFingerprintHeader = "guardgress/add-tls-fingerprint-header"
	ForceSSLRedirect        = "guardgress/force-ssl-redirect"
	WhitelistIpSourceRange  = "guardgress/whitelist-ip-source-range"
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

func IsIpAllowed(annotations map[string]string, ip string) (bool, error) {
	whiteListSourceRange, exists := annotations[WhitelistIpSourceRange]

	if !exists {
		return true, nil
	}

	ranger := cidranger.NewPCTrieRanger()
	for _, network := range strings.Split(whiteListSourceRange, ",") {
		_, parsedNetwork, err := net.ParseCIDR(network)
		if err != nil {
			return false, err
		}
		err = ranger.Insert(cidranger.NewBasicRangerEntry(*parsedNetwork))
		if err != nil {
			return false, err
		}
	}

	return ranger.Contains(net.ParseIP(ip))
}

func IsUserAgentAllowed(annotations map[string]string, userAgent string) bool {
	whitelistAnnotation := annotations[UserAgentWhitelist]
	blacklistAnnotation := annotations[UserAgentBlacklist]

	if isUserAgentListed(whitelistAnnotation, userAgent, "whitelist") {
		return true
	}

	if isUserAgentListed(blacklistAnnotation, userAgent, "blacklist") {
		return false
	}

	return len(whitelistAnnotation) == 0
}

func isUserAgentListed(userAgentList string, userAgent string, listType string) bool {
	if userAgentList == "" {
		return false
	}

	for _, uaPattern := range strings.Split(userAgentList, ",") {
		log.Debug(fmt.Sprintf("Matching user agent %s with pattern %s", userAgent, uaPattern))
		matched, err := regexp.MatchString(uaPattern, userAgent)
		if err != nil {
			log.Errorf("Error matching user agent: %s", err)
			continue
		}
		if matched {
			log.Debugf("User agent got %s: %s", listType, userAgent)
			return true
		}
	}
	return false
}

func TlsFingerprintAnnotationExists(annotations map[string]string) bool {
	_, whitelistExists := annotations[TLSFingerprintWhitelist]
	_, blacklistExists := annotations[TLSFingerprintBlackList]
	_, addTlsHeaderExists := annotations[AddTLSFingerprintHeader]
	return whitelistExists || blacklistExists || addTlsHeaderExists
}

func IsTLSFingerprintAllowed(annotations map[string]string, parsedClientHello models.ParsedClientHello) (bool, string) {
	whitelistAnnotation := annotations[TLSFingerprintWhitelist]
	blacklistAnnotation := annotations[TLSFingerprintBlackList]

	fingerprint := ""
	// fingerprint is allowed if it exists in whitelist
	if ok, fp := isTLSFingerprintListed(whitelistAnnotation, parsedClientHello); ok {
		fingerprint = fp
		return true, fp
	}

	// fingerprint is not allowed if it exists in blacklist
	if ok, fp := isTLSFingerprintListed(blacklistAnnotation, parsedClientHello); ok {
		return false, fp
	}

	// fingerprint is allowed if whitelist is empty and blacklist is not existent
	return len(whitelistAnnotation) == 0, fingerprint
}

func isTLSFingerprintListed(tlsFingerprintList string, parsedClientHello models.ParsedClientHello) (bool, string) {
	if tlsFingerprintList == "" {
		return false, ""
	}

	for _, tlsBlacklistValue := range strings.Split(tlsFingerprintList, ",") {
		if tlsBlacklistValue == parsedClientHello.Ja3 || tlsBlacklistValue == parsedClientHello.Ja3n || tlsBlacklistValue == algorithms.Ja3Digest(parsedClientHello.Ja3) {
			log.Errorf("Ja3 fingerprint got blacklisted: %s", parsedClientHello.Ja3)
			return true, parsedClientHello.Ja3
		}
		if tlsBlacklistValue == parsedClientHello.Ja4 || tlsBlacklistValue == parsedClientHello.Ja4h {
			log.Errorf("Ja4 fingerprint got blacklisted: %s", parsedClientHello.Ja4)
			return true, parsedClientHello.Ja4
		}
	}

	return false, ""
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
