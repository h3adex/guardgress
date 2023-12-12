package server

import (
	"github.com/h3adex/guardgress/pkg/annotations"
	"github.com/h3adex/guardgress/pkg/models"
)

func isRequestAllowed(parsedAnnotations map[string]string, parsedClientHello models.ClientHelloParsed) bool {
	if len(parsedAnnotations) == 0 {
		return true
	}

	if !annotations.IsUserAgentAllowed(parsedAnnotations, parsedClientHello.UserAgent) {
		return false
	}

	if !annotations.IsTLSFingerprintAllowed(parsedAnnotations, parsedClientHello) {
		return false
	}

	return true
}
