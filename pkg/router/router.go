package router

import (
	"crypto/tls"
	"fmt"
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

type RoutingTable struct {
	Ingresses       *v1.IngressList
	TlsCertificates map[string]*tls.Certificate
	IngressLimiters []*limiter.Limiter
}

type RoutingError struct {
	Error      error
	StatusCode int
}

func (r *RoutingTable) Update(payload watcher.Payload) {
	r.Ingresses = payload.Ingresses
	r.TlsCertificates = payload.TlsCertificates
	r.IngressLimiters = payload.IngressLimiters
}

func sortIngressHttpPaths(paths []v1.HTTPIngressPath) []v1.HTTPIngressPath {
	sort.Slice(paths, func(i, j int) bool {
		return paths[i].Path != ""
	})

	return paths
}

func (r *RoutingTable) GetBackend(host, uri, ip string) (*url.URL, map[string]string, RoutingError) {
	for index, ingress := range r.Ingresses.Items {
		for _, rule := range ingress.Spec.Rules {
			if !isHostMatch(rule.Host, host) {
				continue
			}

			for _, path := range sortIngressHttpPaths(rule.HTTP.Paths) {
				if !isPathMatch(path, uri) {
					continue
				}

				if limithandler.IsLimited(r.IngressLimiters[index], ingress.Annotations, ip, path.Path) {
					return nil, nil, RoutingError{Error: fmt.Errorf("rate limited"), StatusCode: 429}
				}

				return buildURL(path, ingress), ingress.Annotations, RoutingError{}
			}
		}
	}

	return nil, nil, RoutingError{Error: fmt.Errorf("not found"), StatusCode: 404}
}

// Helper function to check if the requested URI matches the path
func isPathMatch(path v1.HTTPIngressPath, uri string) bool {
	pathType := path.PathType
	// No PathType annotation should work as PathTypeExact
	if pathType == nil || *pathType == v1.PathTypeExact {
		return path.Path == uri
	}

	// Logic for pathTypeImplementationSpecific, pathTypePrefix
	return strings.HasPrefix(uri, path.Path)
}

// Helper function to build the URL from the Ingress path
func buildURL(path v1.HTTPIngressPath, ingress v1.Ingress) *url.URL {
	return &url.URL{
		Host:   fmt.Sprintf("%s.%s.svc.cluster.local:%d", path.Backend.Service.Name, ingress.Namespace, path.Backend.Service.Port.Number),
		Path:   path.Path,
		Scheme: "http",
	}
}

func (r *RoutingTable) GetTlsCertificate(sni string) (*tls.Certificate, error) {
	if _, ok := os.LookupEnv("FORCE_LOCALHOST_CERT"); ok {
		return r.TlsCertificates["localhost"], nil
	}

	cert, ok := r.TlsCertificates[sni]
	if !ok {
		return nil, fmt.Errorf("no certificate found for sni %s", sni)
	}

	return cert, nil
}

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
