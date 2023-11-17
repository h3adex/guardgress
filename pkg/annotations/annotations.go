package annotations

import (
	"strings"
)

func IsJa3Blacklisted(annotations map[string]string, requestJa3 string) bool {
	tlsBlacklist, ok := annotations["guardgress/tls-blacklist"]
	if ok {
		for _, tlsHash := range strings.Split(tlsBlacklist, ",") {
			if tlsHash == requestJa3 {
				return true
			}
		}
	}

	return false
}

func AddJa3Header(annotations map[string]string) bool {
	addJa3Header, ok := annotations["guardgress/add-ja3-header"]
	if ok && addJa3Header == "true" {
		return true
	}

	return false
}
