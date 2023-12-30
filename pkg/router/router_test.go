package router

import (
	"crypto/tls"
	"github.com/h3adex/guardgress/pkg/mocks"
	"github.com/h3adex/guardgress/pkg/watcher"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/ulule/limiter/v3"
	v1 "k8s.io/api/networking/v1"
	v12 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"os"
	"strings"
	"testing"
)

func init() {
	log.SetLevel(log.DebugLevel)
}

func TestUpdateRoutingTable(t *testing.T) {
	routingTable := RoutingTable{
		Ingresses:       &v1.IngressList{},
		TlsCertificates: mocks.TlsCertificatesMock(),
		IngressLimiters: []*limiter.Limiter{nil, nil, nil},
	}

	routingTable.Update(watcher.Payload{
		Ingresses:       &v1.IngressList{},
		TlsCertificates: mocks.TlsCertificatesMock(),
		IngressLimiters: []*limiter.Limiter{nil, nil, nil, nil},
	})

	assert.Equal(t, len(routingTable.IngressLimiters), 4)
}

func TestGetTlsCertificate(t *testing.T) {
	routingTable := RoutingTable{
		Ingresses:       &v1.IngressList{},
		TlsCertificates: mocks.TlsCertificatesMock(),
		IngressLimiters: []*limiter.Limiter{nil, nil, nil},
	}

	t.Run("test get tls certificate", func(t *testing.T) {
		certificate, err := routingTable.GetTlsCertificate("www.guardgress.com")
		assert.NoError(t, err)
		assert.Equal(t, certificate, &tls.Certificate{Certificate: nil, PrivateKey: nil})

		certificate, err = routingTable.GetTlsCertificate("127.0.0.1")
		assert.NoError(t, err)
	})
}

func TestGetTlsCertificateForceLocalhost(t *testing.T) {
	routingTable := RoutingTable{
		Ingresses:       &v1.IngressList{},
		TlsCertificates: mocks.TlsCertificatesMock(),
		IngressLimiters: []*limiter.Limiter{nil, nil, nil},
	}

	t.Run("test get tls certificate for dev mode", func(t *testing.T) {
		_, ok := os.LookupEnv("FORCE_LOCALHOST_CERT")
		assert.False(t, ok)
		err := os.Setenv("FORCE_LOCALHOST_CERT", "true")
		assert.NoError(t, err)
		_, ok = os.LookupEnv("FORCE_LOCALHOST_CERT")
		assert.True(t, ok)

		// sni does not matter should return localhost cert
		_, err = routingTable.GetTlsCertificate("www.foo.com")
		assert.NoError(t, err)
	})
}

func TestGetBackendExactPathType(t *testing.T) {
	routingTable := RoutingTable{
		Ingresses: &v1.IngressList{
			TypeMeta: v12.TypeMeta{},
			ListMeta: v12.ListMeta{},
			Items: []v1.Ingress{
				mocks.IngressExactPathTypeMock(),
			},
		},
		TlsCertificates: mocks.TlsCertificatesMock(),
		IngressLimiters: []*limiter.Limiter{nil},
	}

	t.Run("test exact path type which is present in mock", func(t *testing.T) {
		url, _, err := routingTable.GetBackend("www.guardgress.com", "/", "127.0.0.1")
		assert.NoError(t, err.Error)
		assert.Equal(t, url.Host, "127.0.0.1.default.svc.cluster.local:10100")
	})

	t.Run("test exact path type which is not present in mock", func(t *testing.T) {
		_, _, err := routingTable.GetBackend("www.guardgress.com", "/abc", "127.0.0.1")
		assert.Error(t, err.Error)
	})
}

func TestWildCardHostsExactPathType(t *testing.T) {
	mock := mocks.IngressExactPathTypeMock()
	mock.Spec.Rules[0].Host = "*.guardgress.com"

	routingTable := RoutingTable{
		Ingresses: &v1.IngressList{
			TypeMeta: v12.TypeMeta{},
			ListMeta: v12.ListMeta{},
			Items: []v1.Ingress{
				mock,
			},
		},
		TlsCertificates: mocks.TlsCertificatesMock(),
		IngressLimiters: []*limiter.Limiter{nil},
	}

	t.Run("test exact path type which is present in mock with wildcard host", func(t *testing.T) {
		url, _, err := routingTable.GetBackend("test.guardgress.com", "/", "127.0.0.1")
		assert.NoError(t, err.Error)
		assert.Equal(t, url.Host, "127.0.0.1.default.svc.cluster.local:10100")
	})

	t.Run("test exact path type which is not present in mock", func(t *testing.T) {
		url, _, err := routingTable.GetBackend("dev.test.guardgress.com", "/", "127.0.0.1")
		assert.NoError(t, err.Error)
		assert.Equal(t, url.Host, "127.0.0.1.default.svc.cluster.local:10100")
	})
}

// No PathType annotation should work as PathTypeExact
func TestGetBackendNoPathType(t *testing.T) {
	routingTable := RoutingTable{
		Ingresses: &v1.IngressList{
			TypeMeta: v12.TypeMeta{},
			ListMeta: v12.ListMeta{},
			Items: []v1.Ingress{
				mocks.IngressNoPathTypeMock(),
			},
		},
		TlsCertificates: mocks.TlsCertificatesMock(),
		IngressLimiters: []*limiter.Limiter{nil},
	}

	t.Run("test no path type which is present in mock", func(t *testing.T) {
		url, _, err := routingTable.GetBackend("www.guardgress.com", "/", "127.0.0.1")
		assert.NoError(t, err.Error)
		assert.Equal(t, url.Host, "127.0.0.1.default.svc.cluster.local:10100")
	})

	t.Run("test no path type which is not present in mock", func(t *testing.T) {
		_, _, err := routingTable.GetBackend("www.guardgress.com", "/abc", "127.0.0.1")
		assert.Error(t, err.Error)
	})
}

func TestGetBackendPathTypePrefix(t *testing.T) {
	routingTable := RoutingTable{
		Ingresses: &v1.IngressList{
			TypeMeta: v12.TypeMeta{},
			ListMeta: v12.ListMeta{},
			Items: []v1.Ingress{
				mocks.IngressPathTypePrefixMock(),
			},
		},
		TlsCertificates: mocks.TlsCertificatesMock(),
		IngressLimiters: []*limiter.Limiter{nil},
	}

	t.Run("test path type prefix which is present in mock /foo", func(t *testing.T) {
		url, _, err := routingTable.GetBackend("www.guardgress.com", "/foo", "127.0.0.1")
		assert.NoError(t, err.Error)
		assert.Equal(t, url.Host, "127.0.0.1.default.svc.cluster.local:10100")
	})

	t.Run("test path type prefix which is not present in mock", func(t *testing.T) {
		_, _, err := routingTable.GetBackend("www.guardgress.com", "/", "127.0.0.1")
		assert.Error(t, err.Error)
	})

	t.Run("test path type prefix which is present in mock /foo/bar", func(t *testing.T) {
		url, _, err := routingTable.GetBackend("www.guardgress.com", "/foo/bar", "127.0.0.1")
		assert.NoError(t, err.Error)
		assert.Equal(t, url.Host, "127.0.0.1.default.svc.cluster.local:10100")
	})
}

// PathTypeImplementationSpecific annotation should work as PathTypePrefix
func TestGetBackendPathTypeImplementationSpecific(t *testing.T) {
	routingTable := RoutingTable{
		Ingresses: &v1.IngressList{
			TypeMeta: v12.TypeMeta{},
			ListMeta: v12.ListMeta{},
			Items: []v1.Ingress{
				mocks.IngressPathTypeImplementationSpecificTypeMock(),
			},
		},
		TlsCertificates: mocks.TlsCertificatesMock(),
		IngressLimiters: []*limiter.Limiter{nil},
	}

	t.Run("test path type implementation specific which is present in mock /foo", func(t *testing.T) {
		url, _, err := routingTable.GetBackend("www.guardgress.com", "/foo", "127.0.0.1")
		assert.NoError(t, err.Error)
		assert.Equal(t, url.Host, "127.0.0.1.default.svc.cluster.local:10100")
	})

	t.Run("test path type implementation specific which is present in mock /foo/bar", func(t *testing.T) {
		url, _, err := routingTable.GetBackend("www.guardgress.com", "/foo/bar", "127.0.0.1")
		assert.NoError(t, err.Error)
		assert.Equal(t, url.Host, "127.0.0.1.default.svc.cluster.local:10100")
	})

	t.Run("test path type implementation specific which is not present in mock", func(t *testing.T) {
		_, _, err := routingTable.GetBackend("www.guardgress.com", "/", "127.0.0.1")
		assert.Error(t, err.Error)
	})
}

func TestGetBackendWithMultipleIngresses(t *testing.T) {
	mockExactPath := mocks.IngressExactPathTypeMock()
	mockExactPath.Spec.Rules[0].Host = "mockExactPath.guardgress.com"
	mockExactPath1 := mocks.IngressExactPathTypeMock()
	mockExactPath1.Spec.Rules[0].Host = "mockExactPath1.guardgress.com"
	mockExactPath1.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number = 20100

	mockNoPath := mocks.IngressNoPathTypeMock()
	mockNoPath.Spec.Rules[0].Host = "mockNoPath.guardgress.com"
	mockNoPath1 := mocks.IngressNoPathTypeMock()
	mockNoPath1.Spec.Rules[0].Host = "mockNoPath1.guardgress.com"
	mockNoPath1.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number = 20100

	mockPathTypePrefix := mocks.IngressPathTypePrefixMock()
	mockPathTypePrefix.Spec.Rules[0].Host = "mockPathTypePrefix.guardgress.com"
	mockPathTypePrefix.Spec.Rules[0].HTTP.Paths[0].Path = "/foo"
	mockPathTypePrefix1 := mocks.IngressPathTypePrefixMock()
	mockPathTypePrefix1.Spec.Rules[0].HTTP.Paths[0].Path = "/bar"
	mockPathTypePrefix1.Spec.Rules[0].Host = "mockPathTypePrefix1.guardgress.com"
	mockPathTypePrefix1.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number = 20100

	mockPathTypeImplementationSpecific := mocks.IngressPathTypeImplementationSpecificTypeMock()
	mockPathTypeImplementationSpecific.Spec.Rules[0].Host = "mockPathTypeImplementationSpecific.guardgress.com"
	mockPathTypeImplementationSpecific.Spec.Rules[0].HTTP.Paths[0].Path = "/foo"
	mockPathTypeImplementationSpecific1 := mocks.IngressPathTypeImplementationSpecificTypeMock()
	mockPathTypeImplementationSpecific1.Spec.Rules[0].HTTP.Paths[0].Path = "/bar"
	mockPathTypeImplementationSpecific1.Spec.Rules[0].Host = "mockPathTypeImplementationSpecific1.guardgress.com"
	mockPathTypeImplementationSpecific1.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number = 20100

	routingTable := RoutingTable{
		Ingresses: &v1.IngressList{
			TypeMeta: v12.TypeMeta{},
			ListMeta: v12.ListMeta{},
			Items: []v1.Ingress{
				mockExactPath,
				mockExactPath1,
				mockNoPath,
				mockNoPath1,
				mockPathTypePrefix,
				mockPathTypePrefix1,
				mockPathTypeImplementationSpecific,
				mockPathTypeImplementationSpecific1,
			},
		},
		TlsCertificates: mocks.TlsCertificatesMock(),
		IngressLimiters: []*limiter.Limiter{nil, nil, nil, nil, nil, nil, nil, nil},
	}

	t.Run("test exact path type which is present in ingresses mockExactPath/", func(t *testing.T) {
		url, _, err := routingTable.GetBackend("mockExactPath.guardgress.com", "/", "")
		assert.NoError(t, err.Error)
		assert.Equal(t, url.Host, "127.0.0.1.default.svc.cluster.local:10100")
	})

	t.Run("test exact path type which is not present in ingresses mockExactPath/foo", func(t *testing.T) {
		_, _, err := routingTable.GetBackend("mockExactPath.guardgress.com", "/foo", "")
		assert.Error(t, err.Error)
	})

	t.Run("test exact path type which is present in ingresses mockExactPath1/", func(t *testing.T) {
		url, _, err := routingTable.GetBackend("mockExactPath1.guardgress.com", "/", "")
		assert.NoError(t, err.Error)
		assert.Equal(t, url.Host, "127.0.0.1.default.svc.cluster.local:20100")
	})

	// mockExactPath1
	t.Run("test exact path type which is not present in ingresses mockExactPath1/foo", func(t *testing.T) {
		_, _, err := routingTable.GetBackend("mockExactPath1.guardgress.com", "/foo", "")
		assert.Error(t, err.Error)
	})

	t.Run("test no path type which is present in ingresses mockNoPath/", func(t *testing.T) {
		url, _, err := routingTable.GetBackend("mockNoPath.guardgress.com", "/", "")
		assert.NoError(t, err.Error)
		assert.Equal(t, url.Host, "127.0.0.1.default.svc.cluster.local:10100")
	})

	t.Run("test no path type which is present in ingresses mockNoPath/foo", func(t *testing.T) {
		url, _, err := routingTable.GetBackend("mockNoPath1.guardgress.com", "/", "")
		assert.NoError(t, err.Error)
		assert.Equal(t, url.Host, "127.0.0.1.default.svc.cluster.local:20100")
	})

	t.Run("test path type prefix which is present in ingresses mockPathTypePrefix/foo", func(t *testing.T) {
		url, _, err := routingTable.GetBackend("mockPathTypePrefix.guardgress.com", "/foo", "")
		assert.NoError(t, err.Error)
		assert.Equal(t, url.Host, "127.0.0.1.default.svc.cluster.local:10100")
	})

	t.Run("test path type prefix which is present in ingresses mockPathTypePrefix/foo/bar", func(t *testing.T) {
		url, _, err := routingTable.GetBackend("mockPathTypePrefix.guardgress.com", "/foo/bar", "")
		assert.NoError(t, err.Error)
		assert.Equal(t, url.Host, "127.0.0.1.default.svc.cluster.local:10100")
	})

	t.Run("test path type prefix which is present in ingresses mockPathTypePrefix1/bar", func(t *testing.T) {
		url, _, err := routingTable.GetBackend("mockPathTypePrefix1.guardgress.com", "/bar", "")
		assert.NoError(t, err.Error)
		assert.Equal(t, url.Host, "127.0.0.1.default.svc.cluster.local:20100")
	})

	t.Run("test path type prefix which is present in ingresses mockPathTypePrefix1/bar/foo", func(t *testing.T) {
		url, _, err := routingTable.GetBackend("mockPathTypePrefix1.guardgress.com", "/bar/foo", "")
		assert.NoError(t, err.Error)
		assert.Equal(t, url.Host, "127.0.0.1.default.svc.cluster.local:20100")
	})

	t.Run("test path type implementation specific which is present in ingresses mockPathTypeImplementationSpecific/foo", func(t *testing.T) {
		url, _, err := routingTable.GetBackend("mockPathTypeImplementationSpecific.guardgress.com", "/foo", "")
		assert.NoError(t, err.Error)
		assert.Equal(t, url.Host, "127.0.0.1.default.svc.cluster.local:10100")
	})

	t.Run("test path type implementation specific which is present in ingresses mockPathTypeImplementationSpecific/foo/bar", func(t *testing.T) {
		url, _, err := routingTable.GetBackend("mockPathTypeImplementationSpecific.guardgress.com", "/foo/bar", "")
		assert.NoError(t, err.Error)
		assert.Equal(t, url.Host, "127.0.0.1.default.svc.cluster.local:10100")
	})

	t.Run("test path type implementation specific which is present in ingresses mockPathTypeImplementationSpecific1/bar", func(t *testing.T) {
		url, _, err := routingTable.GetBackend("mockPathTypeImplementationSpecific1.guardgress.com", "/bar", "")
		assert.NoError(t, err.Error)
		assert.Equal(t, url.Host, "127.0.0.1.default.svc.cluster.local:20100")
	})

	t.Run("test path type implementation specific which is present in ingresses mockPathTypeImplementationSpecific1/bar/foo", func(t *testing.T) {
		url, _, err := routingTable.GetBackend("mockPathTypeImplementationSpecific1.guardgress.com", "/bar/foo", "")
		assert.NoError(t, err.Error)
		assert.Equal(t, url.Host, "127.0.0.1.default.svc.cluster.local:20100")
	})
}

func TestGetBackendWithMultipleIngressesInDifferentNamespaces(t *testing.T) {
	mockExactPath := mocks.IngressExactPathTypeMock()
	mockExactPath.Spec.Rules[0].Host = "mockExactPath.guardgress.com"
	mockExactPath.Namespace = "mockExactPath"

	mockExactPath1 := mocks.IngressExactPathTypeMock()
	mockExactPath1.Spec.Rules[0].Host = "mockExactPath1.guardgress.com"
	mockExactPath1.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number = 20100
	mockExactPath1.Namespace = "mockExactPath1"

	mockNoPath := mocks.IngressNoPathTypeMock()
	mockNoPath.Spec.Rules[0].Host = "mockNoPath.guardgress.com"
	mockNoPath.Namespace = "mockNoPath"

	mockNoPath1 := mocks.IngressNoPathTypeMock()
	mockNoPath1.Spec.Rules[0].Host = "mockNoPath1.guardgress.com"
	mockNoPath1.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number = 20100
	mockNoPath1.Namespace = "mockNoPath1"

	mockPathTypePrefix := mocks.IngressPathTypePrefixMock()
	mockPathTypePrefix.Spec.Rules[0].Host = "mockPathTypePrefix.guardgress.com"
	mockPathTypePrefix.Spec.Rules[0].HTTP.Paths[0].Path = "/foo"
	mockPathTypePrefix.Namespace = "mockPathTypePrefix"

	mockPathTypePrefix1 := mocks.IngressPathTypePrefixMock()
	mockPathTypePrefix1.Spec.Rules[0].HTTP.Paths[0].Path = "/bar"
	mockPathTypePrefix1.Spec.Rules[0].Host = "mockPathTypePrefix1.guardgress.com"
	mockPathTypePrefix1.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number = 20100
	mockPathTypePrefix1.Namespace = "mockPathTypePrefix1"

	mockPathTypeImplementationSpecific := mocks.IngressPathTypeImplementationSpecificTypeMock()
	mockPathTypeImplementationSpecific.Spec.Rules[0].Host = "mockPathTypeImplementationSpecific.guardgress.com"
	mockPathTypeImplementationSpecific.Spec.Rules[0].HTTP.Paths[0].Path = "/foo"
	mockPathTypeImplementationSpecific.Namespace = "mockPathTypeImplementationSpecific"

	mockPathTypeImplementationSpecific1 := mocks.IngressPathTypeImplementationSpecificTypeMock()
	mockPathTypeImplementationSpecific1.Spec.Rules[0].HTTP.Paths[0].Path = "/bar"
	mockPathTypeImplementationSpecific1.Spec.Rules[0].Host = "mockPathTypeImplementationSpecific1.guardgress.com"
	mockPathTypeImplementationSpecific1.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number = 20100
	mockPathTypeImplementationSpecific1.Namespace = "mockPathTypeImplementationSpecific1"

	routingTable := RoutingTable{
		Ingresses: &v1.IngressList{
			TypeMeta: v12.TypeMeta{},
			ListMeta: v12.ListMeta{},
			Items: []v1.Ingress{
				mockExactPath,
				mockExactPath1,
				mockNoPath,
				mockNoPath1,
				mockPathTypePrefix,
				mockPathTypePrefix1,
				mockPathTypeImplementationSpecific,
				mockPathTypeImplementationSpecific1,
			},
		},
		TlsCertificates: mocks.TlsCertificatesMock(),
		IngressLimiters: []*limiter.Limiter{nil, nil, nil, nil, nil, nil, nil, nil},
	}

	t.Run("test exact path type which is present in ingresses mockExactPath/", func(t *testing.T) {
		url, _, err := routingTable.GetBackend("mockExactPath.guardgress.com", "/", "")
		assert.NoError(t, err.Error)
		assert.Equal(t, url.Host, "127.0.0.1.mockExactPath.svc.cluster.local:10100")
	})

	t.Run("test exact path type which is not present in ingresses mockExactPath/foo", func(t *testing.T) {
		_, _, err := routingTable.GetBackend("mockExactPath.guardgress.com", "/foo", "")
		assert.Error(t, err.Error)
	})

	t.Run("test exact path type which is present in ingresses mockExactPath1/", func(t *testing.T) {
		url, _, err := routingTable.GetBackend("mockExactPath1.guardgress.com", "/", "")
		assert.NoError(t, err.Error)
		assert.Equal(t, url.Host, "127.0.0.1.mockExactPath1.svc.cluster.local:20100")
	})

	// mockExactPath1
	t.Run("test exact path type which is not present in ingresses mockExactPath1/foo", func(t *testing.T) {
		_, _, err := routingTable.GetBackend("mockExactPath1.guardgress.com", "/foo", "")
		assert.Error(t, err.Error)
	})

	t.Run("test no path type which is present in ingresses mockNoPath/", func(t *testing.T) {
		url, _, err := routingTable.GetBackend("mockNoPath.guardgress.com", "/", "")
		assert.NoError(t, err.Error)
		assert.Equal(t, url.Host, "127.0.0.1.mockNoPath.svc.cluster.local:10100")
	})

	t.Run("test no path type which is present in ingresses mockNoPath/foo", func(t *testing.T) {
		url, _, err := routingTable.GetBackend("mockNoPath1.guardgress.com", "/", "")
		assert.NoError(t, err.Error)
		assert.Equal(t, url.Host, "127.0.0.1.mockNoPath1.svc.cluster.local:20100")
	})

	t.Run("test path type prefix which is present in ingresses mockPathTypePrefix/foo", func(t *testing.T) {
		url, _, err := routingTable.GetBackend("mockPathTypePrefix.guardgress.com", "/foo", "")
		assert.NoError(t, err.Error)
		assert.Equal(t, url.Host, "127.0.0.1.mockPathTypePrefix.svc.cluster.local:10100")
	})

	t.Run("test path type prefix which is present in ingresses mockPathTypePrefix/foo/bar", func(t *testing.T) {
		url, _, err := routingTable.GetBackend("mockPathTypePrefix.guardgress.com", "/foo/bar", "")
		assert.NoError(t, err.Error)
		assert.Equal(t, url.Host, "127.0.0.1.mockPathTypePrefix.svc.cluster.local:10100")
	})

	t.Run("test path type prefix which is present in ingresses mockPathTypePrefix1/bar", func(t *testing.T) {
		url, _, err := routingTable.GetBackend("mockPathTypePrefix1.guardgress.com", "/bar", "")
		assert.NoError(t, err.Error)
		assert.Equal(t, url.Host, "127.0.0.1.mockPathTypePrefix1.svc.cluster.local:20100")
	})

	t.Run("test path type prefix which is present in ingresses mockPathTypePrefix1/bar/foo", func(t *testing.T) {
		url, _, err := routingTable.GetBackend("mockPathTypePrefix1.guardgress.com", "/bar/foo", "")
		assert.NoError(t, err.Error)
		assert.Equal(t, url.Host, "127.0.0.1.mockPathTypePrefix1.svc.cluster.local:20100")
	})

	t.Run("test path type implementation specific which is present in ingresses mockPathTypeImplementationSpecific/foo", func(t *testing.T) {
		url, _, err := routingTable.GetBackend("mockPathTypeImplementationSpecific.guardgress.com", "/foo", "")
		assert.NoError(t, err.Error)
		assert.Equal(t, url.Host, "127.0.0.1.mockPathTypeImplementationSpecific.svc.cluster.local:10100")
	})

	t.Run("test path type implementation specific which is present in ingresses mockPathTypeImplementationSpecific/foo/bar", func(t *testing.T) {
		url, _, err := routingTable.GetBackend("mockPathTypeImplementationSpecific.guardgress.com", "/foo/bar", "")
		assert.NoError(t, err.Error)
		assert.Equal(t, url.Host, "127.0.0.1.mockPathTypeImplementationSpecific.svc.cluster.local:10100")
	})

	t.Run("test path type implementation specific which is present in ingresses mockPathTypeImplementationSpecific1/bar", func(t *testing.T) {
		url, _, err := routingTable.GetBackend("mockPathTypeImplementationSpecific1.guardgress.com", "/bar", "")
		assert.NoError(t, err.Error)
		assert.Equal(t, url.Host, "127.0.0.1.mockPathTypeImplementationSpecific1.svc.cluster.local:20100")
	})

	t.Run("test path type implementation specific which is present in ingresses mockPathTypeImplementationSpecific1/bar/foo", func(t *testing.T) {
		url, _, err := routingTable.GetBackend("mockPathTypeImplementationSpecific1.guardgress.com", "/bar/foo", "")
		assert.NoError(t, err.Error)
		assert.Equal(t, url.Host, "127.0.0.1.mockPathTypeImplementationSpecific1.svc.cluster.local:20100")
	})
}

func TestRoutingWithMultipleIngressPaths(t *testing.T) {
	pathTypePrefix := v1.PathTypePrefix
	ingressPathTypePrefix := v1.Ingress{
		TypeMeta: v12.TypeMeta{},
		ObjectMeta: v12.ObjectMeta{
			Namespace:   "default",
			Annotations: map[string]string{},
		},
		Spec: v1.IngressSpec{
			IngressClassName: nil,
			DefaultBackend:   nil,
			TLS:              nil,
			Rules: []v1.IngressRule{
				{
					Host: "example.guardgress.com",
					IngressRuleValue: v1.IngressRuleValue{
						HTTP: &v1.HTTPIngressRuleValue{
							Paths: []v1.HTTPIngressPath{
								{
									Path:     "/",
									PathType: &pathTypePrefix,
									Backend: v1.IngressBackend{
										Service: &v1.IngressServiceBackend{
											Name: "web-shop",
											Port: v1.ServiceBackendPort{
												Name:   "",
												Number: 8080,
											},
										},
										Resource: nil,
									},
								},
							},
						},
					},
				},
			},
		},
		Status: v1.IngressStatus{},
	}
	ingressPathTypePrefix2 := v1.Ingress{
		TypeMeta: v12.TypeMeta{},
		ObjectMeta: v12.ObjectMeta{
			Namespace:   "default",
			Annotations: map[string]string{},
		},
		Spec: v1.IngressSpec{
			IngressClassName: nil,
			DefaultBackend:   nil,
			TLS:              nil,
			Rules: []v1.IngressRule{
				{
					Host: "example.guardgress.com",
					IngressRuleValue: v1.IngressRuleValue{
						HTTP: &v1.HTTPIngressRuleValue{
							Paths: []v1.HTTPIngressPath{
								{
									Path:     "/products",
									PathType: &pathTypePrefix,
									Backend: v1.IngressBackend{
										Service: &v1.IngressServiceBackend{
											Name: "products",
											Port: v1.ServiceBackendPort{
												Name:   "",
												Number: 8080,
											},
										},
										Resource: nil,
									},
								},
							},
						},
					},
				},
			},
		},
		Status: v1.IngressStatus{},
	}
	ingressNoPathType := v1.Ingress{
		TypeMeta: v12.TypeMeta{},
		ObjectMeta: v12.ObjectMeta{
			Namespace: "default",
			Annotations: map[string]string{
				"guardgress/user-agent-blacklist": "chrome101",
			},
		},
		Spec: v1.IngressSpec{
			IngressClassName: nil,
			DefaultBackend:   nil,
			TLS:              nil,
			Rules: []v1.IngressRule{
				{
					Host: "example.guardgress.com",
					IngressRuleValue: v1.IngressRuleValue{
						HTTP: &v1.HTTPIngressRuleValue{
							Paths: []v1.HTTPIngressPath{
								{
									Path: "/admin",
									Backend: v1.IngressBackend{
										Service: &v1.IngressServiceBackend{
											Name: "admin-dashboard",
											Port: v1.ServiceBackendPort{
												Name:   "",
												Number: 9090,
											},
										},
										Resource: nil,
									},
								},
							},
						},
					},
				},
			},
		},
		Status: v1.IngressStatus{},
	}

	routingTable := RoutingTable{
		Ingresses: &v1.IngressList{
			TypeMeta: v12.TypeMeta{},
			ListMeta: v12.ListMeta{},
			Items:    []v1.Ingress{ingressPathTypePrefix, ingressNoPathType, ingressPathTypePrefix2},
		},
		TlsCertificates: mocks.TlsCertificatesMock(),
		IngressLimiters: []*limiter.Limiter{nil, nil, nil},
	}

	t.Run("test if exact path match gets selected at first /admin", func(t *testing.T) {
		// admin route should be matched first since we are checking pathType Exact first
		url, annotations, err := routingTable.GetBackend("example.guardgress.com", "/admin", "")
		assert.NoError(t, err.Error)
		assert.True(t, len(annotations) > 0)
		assert.True(t, strings.Contains(url.Host, "admin-dashboard"))
	})

	t.Run("test if path type prefix gets selected /products", func(t *testing.T) {
		url, annotations, err := routingTable.GetBackend("example.guardgress.com", "/products", "")
		assert.NoError(t, err.Error)
		assert.True(t, len(annotations) == 0)
		assert.True(t, strings.Contains(url.Host, "products"))

		url, annotations, err = routingTable.GetBackend("example.guardgress.com", "/products/", "")
		assert.NoError(t, err.Error)
		assert.True(t, len(annotations) == 0)
		assert.True(t, strings.Contains(url.Host, "products"))

		url, annotations, err = routingTable.GetBackend("example.guardgress.com", "/products/abc", "")
		assert.NoError(t, err.Error)
		assert.True(t, len(annotations) == 0)
		assert.True(t, strings.Contains(url.Host, "products"))
	})

	t.Run("test if path type prefix gets selected at last /", func(t *testing.T) {
		// admin route should be matched at last since it is not path type exact
		url, annotations, err := routingTable.GetBackend("example.guardgress.com", "/", "")
		assert.NoError(t, err.Error)
		assert.True(t, len(annotations) == 0)
		assert.True(t, strings.Contains(url.Host, "web-shop"))

		url, annotations, err = routingTable.GetBackend("example.guardgress.com", "/blog", "")
		assert.NoError(t, err.Error)
		assert.True(t, len(annotations) == 0)
		assert.True(t, strings.Contains(url.Host, "web-shop"))

	})

}

func TestGetBackendJenkinsRealLifeExample(t *testing.T) {
	pathTypeImplementationSpecific := v1.PathTypeImplementationSpecific
	jenkinsMock := v1.Ingress{
		TypeMeta: v12.TypeMeta{},
		ObjectMeta: v12.ObjectMeta{
			Namespace: "default",
		},
		Spec: v1.IngressSpec{
			IngressClassName: nil,
			DefaultBackend:   nil,
			TLS:              nil,
			Rules: []v1.IngressRule{
				{
					Host: "jenkins.guardgress.com",
					IngressRuleValue: v1.IngressRuleValue{
						HTTP: &v1.HTTPIngressRuleValue{
							Paths: []v1.HTTPIngressPath{
								{
									PathType: &pathTypeImplementationSpecific,
									Backend: v1.IngressBackend{
										Service: &v1.IngressServiceBackend{
											Name: "jenkins",
											Port: v1.ServiceBackendPort{
												Name:   "",
												Number: 8080,
											},
										},
										Resource: nil,
									},
								},
								{
									Path:     "/wsagents",
									PathType: &pathTypeImplementationSpecific,
									Backend: v1.IngressBackend{
										Service: &v1.IngressServiceBackend{
											Name: "jenkins-wssocket",
											Port: v1.ServiceBackendPort{
												Name:   "",
												Number: 8080,
											},
										},
										Resource: nil,
									},
								},
								{
									Path:     "/github-webhook/",
									PathType: &pathTypeImplementationSpecific,
									Backend: v1.IngressBackend{
										Service: &v1.IngressServiceBackend{
											Name: "jenkins-webhook",
											Port: v1.ServiceBackendPort{
												Name:   "",
												Number: 8080,
											},
										},
										Resource: nil,
									},
								},
							},
						},
					},
				},
			},
		},
		Status: v1.IngressStatus{},
	}

	routingTable := RoutingTable{
		Ingresses: &v1.IngressList{
			TypeMeta: v12.TypeMeta{},
			ListMeta: v12.ListMeta{},
			Items:    []v1.Ingress{jenkinsMock},
		},
		TlsCertificates: mocks.TlsCertificatesMock(),
		IngressLimiters: []*limiter.Limiter{nil},
	}

	t.Run("test path type implementation specific for jenkins", func(t *testing.T) {
		url, _, err := routingTable.GetBackend("jenkins.guardgress.com", "/", "")
		assert.NoError(t, err.Error)
		assert.Equal(t, url.Host, "jenkins.default.svc.cluster.local:8080")
	})

	t.Run("test path type implementation specific for jenkins /job/system-tests/", func(t *testing.T) {
		url, _, err := routingTable.GetBackend("jenkins.guardgress.com", "/job/system-tests/", "")
		assert.NoError(t, err.Error)
		assert.Equal(t, url.Host, "jenkins.default.svc.cluster.local:8080")
	})

	t.Run("test path type implementation specific for jenkins /wsagents/", func(t *testing.T) {
		url, _, err := routingTable.GetBackend("jenkins.guardgress.com", "/wsagents/", "")
		assert.NoError(t, err.Error)
		assert.Equal(t, url.Host, "jenkins-wssocket.default.svc.cluster.local:8080")
	})

	t.Run("test path type implementation specific for jenkins /github-webhook/", func(t *testing.T) {
		url, _, err := routingTable.GetBackend("jenkins.guardgress.com", "/github-webhook/", "")
		assert.NoError(t, err.Error)
		assert.Equal(t, url.Host, "jenkins-webhook.default.svc.cluster.local:8080")
	})

}

func TestCertManagerImplementation(t *testing.T) {
	mock := mocks.IngressPathTypeImplementationSpecificTypeMock()
	mock.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number = 8089
	mock.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Name = "cm-acme-http-solver-mqvwg"
	mock.Spec.Rules[0].HTTP.Paths[0].Path = "/.well-known/acme-challenge/5XSJIlrUE9OZl_Og7-Y--vIM2eeGhnvSXJLSejioqcM"

	routingTable := RoutingTable{
		Ingresses: &v1.IngressList{
			TypeMeta: v12.TypeMeta{},
			ListMeta: v12.ListMeta{},
			Items: []v1.Ingress{
				mock,
			},
		},
		TlsCertificates: mocks.TlsCertificatesMock(),
		IngressLimiters: []*limiter.Limiter{nil},
	}

	t.Run("test cert_manager well-known request implementation", func(t *testing.T) {
		url, _, err := routingTable.GetBackend("www.guardgress.com", "/.well-known/acme-challenge/5XSJIlrUE9OZl_Og7-Y--vIM2eeGhnvSXJLSejioqcM", "127.0.0.1")
		assert.NoError(t, err.Error)
		assert.Equal(t, mock.Spec.Rules[0].HTTP.Paths[0].Path, url.Path)
		assert.Equal(t, "cm-acme-http-solver-mqvwg.default.svc.cluster.local:8089", url.Host)
	})
}
