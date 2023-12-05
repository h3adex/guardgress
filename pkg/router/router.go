package router

import (
	"crypto/tls"
	"fmt"
	"github.com/h3adex/guardgress/pkg/limitHandler"
	"github.com/h3adex/guardgress/pkg/watcher"
	"github.com/ulule/limiter/v3"
	v1 "k8s.io/api/networking/v1"
	"net/url"
	"os"
	"regexp"
	"strings"
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

func (r *RoutingTable) GetBackend(host, uri, ip string) (*url.URL, map[string]string, RoutingError) {
	pathTypePrefix := v1.PathTypePrefix
	pathTypeImplementationSpecific := v1.PathTypeImplementationSpecific
	pathTypeExact := v1.PathTypeExact

	for index, ingress := range r.Ingresses.Items {
		if ingress.Spec.Rules == nil {
			continue
		}

		for _, rule := range ingress.Spec.Rules {
			if !isHostMatch(rule.Host, host) {
				continue
			}

			for _, path := range rule.HTTP.Paths {
				// No PathType annotation should work as PathTypeExact
				if path.PathType == nil || *path.PathType == pathTypeExact {
					if path.Path == uri {
						if limitHandler.IpIsLimited(
							r.IngressLimiters[index],
							ingress.Annotations,
							ip,
						) {
							return &url.URL{
									Host:   "",
									Scheme: "",
								}, make(map[string]string),
								RoutingError{
									Error:      fmt.Errorf("rate limited"),
									StatusCode: 429,
								}
						}

						return &url.URL{
							Host: fmt.Sprintf(
								"%s:%d",
								path.Backend.Service.Name,
								path.Backend.Service.Port.Number,
							),
							Scheme: "http",
						}, ingress.Annotations, RoutingError{}
					}
				}

				if (path.PathType != nil) && (*path.PathType == pathTypePrefix || *path.PathType == pathTypeImplementationSpecific) {
					if strings.HasPrefix(uri, path.Path) {
						if limitHandler.IpIsLimited(
							r.IngressLimiters[index],
							ingress.Annotations,
							ip,
						) {
							return &url.URL{
									Host:   "",
									Scheme: "",
								}, make(map[string]string),
								RoutingError{
									Error:      fmt.Errorf("rate limited"),
									StatusCode: 429,
								}
						}

						return &url.URL{
							Host: fmt.Sprintf(
								"%s:%d",
								path.Backend.Service.Name,
								path.Backend.Service.Port.Number,
							),
							Scheme: "http",
						}, ingress.Annotations, RoutingError{}
					}
				}
			}
		}
	}

	return &url.URL{
			Host:   "",
			Scheme: "",
		}, make(map[string]string),
		RoutingError{
			Error:      fmt.Errorf("not found"),
			StatusCode: 404,
		}
}

func (r *RoutingTable) GetTlsCertificate(sni string) (*tls.Certificate, error) {
	if len(os.Getenv("FORCE_LOCALHOST_CERT")) > 0 {
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
