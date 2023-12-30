package router

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/h3adex/guardgress/pkg/limithandler"
	"github.com/h3adex/guardgress/pkg/watcher"
	"github.com/ulule/limiter/v3"
	v1 "k8s.io/api/networking/v1"
)

// RoutingTable represents the routing information for the application.
type RoutingTable struct {
	Ingresses       *v1.IngressList
	TlsCertificates map[string]*tls.Certificate
	IngressLimiters []*limiter.Limiter
}

// RoutingError represents an error during routing along with an HTTP status code.
type RoutingError struct {
	Error      error
	StatusCode int
}

// Update updates the routing table with new payload.
func (r *RoutingTable) Update(payload watcher.Payload) {
	r.Ingresses = payload.Ingresses
	r.TlsCertificates = payload.TlsCertificates
	r.IngressLimiters = payload.IngressLimiters
}

// GetBackend retrieves the backend URL based on host and URI.
func (r *RoutingTable) GetBackend(host, uri, ip string) (*url.URL, map[string]string, RoutingError) {
	var exactMatchPaths, prefixMatchPaths []v1.HTTPIngressPath

	// Collect all exact and prefix paths
	for _, ingress := range r.Ingresses.Items {
		for _, rule := range ingress.Spec.Rules {
			if !isHostMatch(rule.Host, host) {
				continue
			}

			for _, path := range rule.HTTP.Paths {
				pathType := path.PathType
				if pathType == nil || *pathType == v1.PathTypeExact {
					exactMatchPaths = append(exactMatchPaths, path)
				} else if *pathType == v1.PathTypePrefix || *pathType == v1.PathTypeImplementationSpecific {
					prefixMatchPaths = append(prefixMatchPaths, path)
				}
			}
		}
	}

	// Try to match exact paths first
	for _, path := range r.sortByPathSpecificity(exactMatchPaths) {
		if path.Path == uri {
			return r.processPathMatch(path, ip)
		}
	}

	// Try prefix paths if no exact match
	for _, path := range r.sortByPathSpecificity(prefixMatchPaths) {
		if strings.HasPrefix(uri, path.Path) {
			return r.processPathMatch(path, ip)
		}
	}

	return nil, nil, RoutingError{Error: fmt.Errorf("not found"), StatusCode: http.StatusNotFound}
}

// sortByPathSpecificity sorts HTTP ingress paths by their specificity.
func (r *RoutingTable) sortByPathSpecificity(paths []v1.HTTPIngressPath) []v1.HTTPIngressPath {
	sort.Slice(paths, func(i, j int) bool {
		return len(paths[i].Path) > len(paths[j].Path)
	})
	return paths
}

// processPathMatch processes a matched path and returns the corresponding backend URL and annotations.
func (r *RoutingTable) processPathMatch(path v1.HTTPIngressPath, ip string) (*url.URL, map[string]string, RoutingError) {
	ingress, ingressLimiter, err := r.findIngressForPath(path)
	if err != nil {
		return nil, nil, RoutingError{Error: err, StatusCode: http.StatusServiceUnavailable}
	}

	if limithandler.IsLimited(ingressLimiter, ingress.Annotations, ip, path.Path) {
		return nil, nil, RoutingError{Error: fmt.Errorf("rate limited"), StatusCode: http.StatusTooManyRequests}
	}

	return buildURL(path, ingress), ingress.Annotations, RoutingError{}
}

// findIngressForPath finds the Ingress for a given path and returns it along with the corresponding limiter.
func (r *RoutingTable) findIngressForPath(path v1.HTTPIngressPath) (v1.Ingress, *limiter.Limiter, error) {
	for index, ingress := range r.Ingresses.Items {
		for _, rule := range ingress.Spec.Rules {
			for _, p := range rule.HTTP.Paths {
				if p == path {
					return ingress, r.IngressLimiters[index], nil
				}
			}
		}
	}
	return v1.Ingress{}, nil, fmt.Errorf("ingress not found for path: %s", path.Path)
}

// buildURL builds the backend URL from an ingress path.
func buildURL(path v1.HTTPIngressPath, ingress v1.Ingress) *url.URL {
	return &url.URL{
		Host:   fmt.Sprintf("%s.%s.svc.cluster.local:%d", path.Backend.Service.Name, ingress.Namespace, path.Backend.Service.Port.Number),
		Path:   path.Path,
		Scheme: "http",
	}
}

// isHostMatch checks if the given rule host matches the request host.
func isHostMatch(ruleHost, requestHost string) bool {
	if ruleHost == requestHost {
		return true
	}

	if strings.HasPrefix(ruleHost, "*.") {
		ruleHost = ruleHost[2:]
		wildcardPattern := strings.ReplaceAll(regexp.QuoteMeta(ruleHost), "\\*", ".*")
		match, err := regexp.MatchString(wildcardPattern, requestHost)
		return match && err == nil
	}

	return false
}

// GetTlsCertificate retrieves the TLS certificate for the given SNI.
func (r *RoutingTable) GetTlsCertificate(sni string) (*tls.Certificate, error) {
	if _, ok := os.LookupEnv("FORCE_LOCALHOST_CERT"); ok {
		return r.TlsCertificates["localhost"], nil
	}

	cert, ok := r.TlsCertificates[sni]
	if !ok {
		return nil, fmt.Errorf("no TLS certificate found for SNI: %s", sni)
	}

	return cert, nil
}
