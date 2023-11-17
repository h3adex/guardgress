package router

import (
	"fmt"
	"github.com/h3adex/guardgress/internal/crypto/tls"
	"github.com/h3adex/guardgress/pkg/watcher"
	v1 "k8s.io/api/networking/v1"
	"net/url"
	"regexp"
	"strings"
)

type RoutingTable struct {
	Ingresses       *v1.IngressList
	TlsCertificates map[string]*tls.Certificate
	DevMode         bool
}

func (r *RoutingTable) Update(payload watcher.Payload) {
	r.Ingresses = payload.Ingresses
	r.TlsCertificates = payload.TlsCertificates
}

func (r *RoutingTable) GetBackend(host string, uri string) (*url.URL, map[string]string, error) {
	pathTypePrefix := v1.PathTypePrefix
	pathTypeImplementationSpecific := v1.PathTypeImplementationSpecific
	pathTypeExact := v1.PathTypeExact

	for _, ingress := range r.Ingresses.Items {
		if ingress.Spec.Rules == nil {
			continue
		}

		for _, rule := range ingress.Spec.Rules {
			if !isHostMatch(rule.Host, host) {
				continue
			}

			for _, path := range rule.HTTP.Paths {
				if path.PathType == nil {
					if path.Path == uri {
						return &url.URL{
							Host:   fmt.Sprintf("%s:%d", path.Backend.Service.Name, path.Backend.Service.Port.Number),
							Scheme: "http",
						}, ingress.Annotations, nil
					}
				}

				switch *path.PathType {
				case pathTypeExact:
					if path.Path == uri {
						return &url.URL{
							Host:   fmt.Sprintf("%s:%d", path.Backend.Service.Name, path.Backend.Service.Port.Number),
							Scheme: "http",
						}, ingress.Annotations, nil
					}

				case pathTypePrefix, pathTypeImplementationSpecific:
					if strings.HasPrefix(uri, path.Path) {
						return &url.URL{
							Host:   fmt.Sprintf("%s:%d", path.Backend.Service.Name, path.Backend.Service.Port.Number),
							Scheme: "http",
						}, ingress.Annotations, nil
					}
				}
			}
		}
	}

	return &url.URL{Host: "", Scheme: ""}, make(map[string]string), fmt.Errorf("no service found for host %s", host)
}

func (r *RoutingTable) GetTlsCertificate(sni string) (*tls.Certificate, error) {
	/* used for development */
	fmt.Println(r.TlsCertificates)
	if r.DevMode {
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
