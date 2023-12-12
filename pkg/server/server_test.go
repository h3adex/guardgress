// If you want to run this tests you have to edit your /etc/hosts file and add the following line:
// 127.0.0.1 127.0.0.1.default.svc.cluster.local
// 127.0.0.1 127.0.0.1.test.svc.cluster.local
// TODO: is the a better way to do this? Editing /etc/hosts might no be possible in some environments.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/h3adex/guardgress/pkg/limitHandler"
	"github.com/h3adex/guardgress/pkg/mocks"
	"github.com/h3adex/guardgress/pkg/router"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/ulule/limiter/v3"
	"io"
	v1 "k8s.io/api/networking/v1"
	v12 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

var mockServerResponse = "mock-svc"
var testReverseProxyConfig = &Config{
	Host:    "127.0.0.1",
	Port:    10101,
	TlsPort: 10102,
}

func init() {
	log.SetLevel(log.DebugLevel)
}

func TestHTTPRequest(t *testing.T) {
	mockServerPort := freePort()
	mockServerAddress := fmt.Sprintf("127.0.0.1.default.svc.cluster.local:%d", mockServerPort)
	testReverseProxyConfig.Port = freePort()
	testReverseProxyConfig.TlsPort = freePort()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startMockServer(mockServerAddress, ctx)

	srv := New(testReverseProxyConfig)

	ingressExactPathMock := mocks.IngressExactPathTypeMock()
	ingressExactPathMock.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number = int32(mockServerPort)
	ingressLimiter := limitHandler.GetIngressLimiter(ingressExactPathMock)

	srv.RoutingTable = &router.RoutingTable{
		Ingresses: &v1.IngressList{
			TypeMeta: v12.TypeMeta{},
			ListMeta: v12.ListMeta{},
			Items: []v1.Ingress{
				ingressExactPathMock,
			},
		},
		TlsCertificates: mocks.TlsCertificatesMock(),
		IngressLimiters: []*limiter.Limiter{ingressLimiter},
	}

	go func() {
		srv.Run(ctx)
	}()

	waitForServer(ctx, testReverseProxyConfig.Port)

	// check if reverse proxy works for http request
	req, err := http.NewRequest(
		"GET",
		fmt.Sprintf("http://%s:%d", testReverseProxyConfig.Host, testReverseProxyConfig.Port),
		nil,
	)
	assert.NoError(t, err)
	req.Host = srv.RoutingTable.Ingresses.Items[0].Spec.Rules[0].Host

	res, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)
	bs, err := io.ReadAll(res.Body)
	assert.NoError(t, err)
	_ = res.Body.Close()
	assert.Equal(t, mockServerResponse, string(bs))
}

func TestHTTPSRequest(t *testing.T) {
	mockServerPort := freePort()
	mockServerAddress := fmt.Sprintf("127.0.0.1.default.svc.cluster.local:%d", mockServerPort)
	testReverseProxyConfig.Port = freePort()
	testReverseProxyConfig.TlsPort = freePort()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startMockServer(mockServerAddress, ctx)

	srv := New(testReverseProxyConfig)

	ingressExactPathMock := mocks.IngressExactPathTypeMock()
	ingressExactPathMock.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number = int32(mockServerPort)
	ingressLimiter := limitHandler.GetIngressLimiter(ingressExactPathMock)

	srv.RoutingTable = &router.RoutingTable{
		Ingresses: &v1.IngressList{
			TypeMeta: v12.TypeMeta{},
			ListMeta: v12.ListMeta{},
			Items: []v1.Ingress{
				ingressExactPathMock,
			},
		},
		TlsCertificates: mocks.TlsCertificatesMock(),
		IngressLimiters: []*limiter.Limiter{ingressLimiter},
	}

	go func() {
		srv.Run(ctx)
	}()

	waitForServer(ctx, testReverseProxyConfig.Port)

	// check if reverse proxy works for https request
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	req, err := http.NewRequest(
		"GET",
		fmt.Sprintf("https://%s:%d", testReverseProxyConfig.Host, testReverseProxyConfig.TlsPort),
		nil,
	)
	assert.NoError(t, err)
	req.Host = srv.RoutingTable.Ingresses.Items[0].Spec.Rules[0].Host

	res, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)
	bs, err := io.ReadAll(res.Body)
	assert.NoError(t, err)
	_ = res.Body.Close()
	assert.Equal(t, mockServerResponse, string(bs))
}

func TestTlsFingerprintingAddHeader(t *testing.T) {
	mockServerPort := freePort()
	mockServerAddress := fmt.Sprintf("127.0.0.1.default.svc.cluster.local:%d", mockServerPort)
	testReverseProxyConfig.Port = freePort()
	testReverseProxyConfig.TlsPort = freePort()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startMockServer(mockServerAddress, ctx)

	srv := New(testReverseProxyConfig)

	ingressExactPathMock := mocks.IngressExactPathTypeMock()
	ingressExactPathMock.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number = int32(mockServerPort)
	ingressExactPathMock.Annotations = map[string]string{"guardgress/add-tls-fingerprint-header": "true"}
	ingressLimiter := limitHandler.GetIngressLimiter(ingressExactPathMock)

	srv.RoutingTable = &router.RoutingTable{
		Ingresses: &v1.IngressList{
			TypeMeta: v12.TypeMeta{},
			ListMeta: v12.ListMeta{},
			Items: []v1.Ingress{
				ingressExactPathMock,
			},
		},
		TlsCertificates: mocks.TlsCertificatesMock(),
		IngressLimiters: []*limiter.Limiter{ingressLimiter},
	}

	go func() {
		srv.Run(ctx)
	}()

	waitForServer(ctx, testReverseProxyConfig.Port)

	// check if reverse proxy returns tls fingerprints
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	req, err := http.NewRequest(
		"GET",
		fmt.Sprintf("https://%s:%d", testReverseProxyConfig.Host, testReverseProxyConfig.TlsPort),
		nil,
	)
	assert.NoError(t, err)
	req.Host = srv.RoutingTable.Ingresses.Items[0].Spec.Rules[0].Host

	res, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)
	assert.NoError(t, err)
	_ = res.Body.Close()

	ja3TlsFingerprint := res.Header.Get("X-Ja3-Fingerprint")
	ja4TlsFingerprint := res.Header.Get("X-Ja4-Fingerprint")
	assert.True(t, len(ja3TlsFingerprint) > 1)
	assert.True(t, len(ja4TlsFingerprint) > 1)

	// test if the fingerprint block works
	srv.RoutingTable.Ingresses.Items[0].Annotations = map[string]string{
		"guardgress/tls-fingerprint-blacklist": fmt.Sprintf("%s,%s", ja3TlsFingerprint, ja4TlsFingerprint),
	}
	// should be forbidden
	res, err = http.DefaultClient.Do(req)
	assert.Equal(t, 403, res.StatusCode)
}

func TestUserAgentBlacklist(t *testing.T) {
	mockServerPort := freePort()
	mockServerAddress := fmt.Sprintf("127.0.0.1.default.svc.cluster.local:%d", mockServerPort)
	testReverseProxyConfig.Port = freePort()
	testReverseProxyConfig.TlsPort = freePort()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startMockServer(mockServerAddress, ctx)

	srv := New(testReverseProxyConfig)

	ingressExactPathMock := mocks.IngressExactPathTypeMock()
	ingressExactPathMock.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number = int32(mockServerPort)
	ingressExactPathMock.Annotations = map[string]string{
		"guardgress/user-agent-blacklist": "curl/7.64.*,curl/7.65.*",
	}
	ingressLimiter := limitHandler.GetIngressLimiter(ingressExactPathMock)

	srv.RoutingTable = &router.RoutingTable{
		Ingresses: &v1.IngressList{
			TypeMeta: v12.TypeMeta{},
			ListMeta: v12.ListMeta{},
			Items: []v1.Ingress{
				ingressExactPathMock,
			},
		},
		TlsCertificates: mocks.TlsCertificatesMock(),
		IngressLimiters: []*limiter.Limiter{ingressLimiter},
	}

	go func() {
		srv.Run(ctx)
	}()

	waitForServer(ctx, testReverseProxyConfig.Port)

	// check if user agent block works
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	t.Run("test user_agent curl/7.64.1 should be blocked", func(t *testing.T) {
		req, err := http.NewRequest(
			"GET",
			fmt.Sprintf("https://%s:%d", testReverseProxyConfig.Host, testReverseProxyConfig.TlsPort),
			nil,
		)
		req.Header.Add("User-Agent", "curl/7.64.1")
		assert.NoError(t, err)
		req.Host = srv.RoutingTable.Ingresses.Items[0].Spec.Rules[0].Host

		res, err := http.DefaultClient.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, 403, res.StatusCode)
	})

	t.Run("test user_agent curl/7.64.2 should be blocked", func(t *testing.T) {
		req, err := http.NewRequest(
			"GET",
			fmt.Sprintf("https://%s:%d", testReverseProxyConfig.Host, testReverseProxyConfig.TlsPort),
			nil,
		)
		req.Header.Add("User-Agent", "curl/7.64.2")
		assert.NoError(t, err)
		req.Host = srv.RoutingTable.Ingresses.Items[0].Spec.Rules[0].Host

		res, err := http.DefaultClient.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, 403, res.StatusCode)
	})

	t.Run("test user_agent curl/7.66.3 should not be blocked", func(t *testing.T) {
		req, err := http.NewRequest(
			"GET",
			fmt.Sprintf("https://%s:%d", testReverseProxyConfig.Host, testReverseProxyConfig.TlsPort),
			nil,
		)
		req.Header.Add("User-Agent", "curl/7.66.3")
		assert.NoError(t, err)
		req.Host = srv.RoutingTable.Ingresses.Items[0].Spec.Rules[0].Host

		res, err := http.DefaultClient.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, 200, res.StatusCode)
	})
}

func TestUserAgentWhitelist(t *testing.T) {
	mockServerPort := freePort()
	mockServerAddress := fmt.Sprintf("127.0.0.1.default.svc.cluster.local:%d", mockServerPort)
	testReverseProxyConfig.Port = freePort()
	testReverseProxyConfig.TlsPort = freePort()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startMockServer(mockServerAddress, ctx)

	srv := New(testReverseProxyConfig)

	ingressExactPathMock := mocks.IngressExactPathTypeMock()
	ingressExactPathMock.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number = int32(mockServerPort)
	ingressExactPathMock.Annotations = map[string]string{
		"guardgress/user-agent-whitelist": "curl/7.64.*,curl/7.65.*",
	}
	ingressLimiter := limitHandler.GetIngressLimiter(ingressExactPathMock)

	srv.RoutingTable = &router.RoutingTable{
		Ingresses: &v1.IngressList{
			TypeMeta: v12.TypeMeta{},
			ListMeta: v12.ListMeta{},
			Items: []v1.Ingress{
				ingressExactPathMock,
			},
		},
		TlsCertificates: mocks.TlsCertificatesMock(),
		IngressLimiters: []*limiter.Limiter{ingressLimiter},
	}

	go func() {
		srv.Run(ctx)
	}()

	waitForServer(ctx, testReverseProxyConfig.Port)

	// check if user agent block works
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	t.Run("test user_agent curl/7.64.1 should not be blocked", func(t *testing.T) {
		req, err := http.NewRequest(
			"GET",
			fmt.Sprintf("https://%s:%d", testReverseProxyConfig.Host, testReverseProxyConfig.TlsPort),
			nil,
		)
		req.Header.Add("User-Agent", "curl/7.64.1")
		assert.NoError(t, err)
		req.Host = srv.RoutingTable.Ingresses.Items[0].Spec.Rules[0].Host

		res, err := http.DefaultClient.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, 200, res.StatusCode)
	})

	t.Run("test user_agent curl/7.64.2 should not be blocked", func(t *testing.T) {
		req, err := http.NewRequest(
			"GET",
			fmt.Sprintf("https://%s:%d", testReverseProxyConfig.Host, testReverseProxyConfig.TlsPort),
			nil,
		)
		req.Header.Add("User-Agent", "curl/7.64.2")
		assert.NoError(t, err)
		req.Host = srv.RoutingTable.Ingresses.Items[0].Spec.Rules[0].Host

		res, err := http.DefaultClient.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, 200, res.StatusCode)
	})

	t.Run("test user_agent curl/7.66.3 should be blocked", func(t *testing.T) {
		req, err := http.NewRequest(
			"GET",
			fmt.Sprintf("https://%s:%d", testReverseProxyConfig.Host, testReverseProxyConfig.TlsPort),
			nil,
		)
		req.Header.Add("User-Agent", "curl/7.66.3")
		assert.NoError(t, err)
		req.Host = srv.RoutingTable.Ingresses.Items[0].Spec.Rules[0].Host

		res, err := http.DefaultClient.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, 403, res.StatusCode)
	})
}

func TestUserAgentBlackAndWhitelist(t *testing.T) {
	mockServerPort := freePort()
	mockServerAddress := fmt.Sprintf("127.0.0.1.default.svc.cluster.local:%d", mockServerPort)
	testReverseProxyConfig.Port = freePort()
	testReverseProxyConfig.TlsPort = freePort()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startMockServer(mockServerAddress, ctx)

	srv := New(testReverseProxyConfig)

	ingressExactPathMock := mocks.IngressExactPathTypeMock()
	ingressExactPathMock.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number = int32(mockServerPort)
	ingressExactPathMock.Annotations = map[string]string{
		"guardgress/user-agent-whitelist": "curl/7.64.*",
		"guardgress/user-agent-blacklist": "curl/7.64.*,curl/7.65.*",
	}
	ingressLimiter := limitHandler.GetIngressLimiter(ingressExactPathMock)

	srv.RoutingTable = &router.RoutingTable{
		Ingresses: &v1.IngressList{
			TypeMeta: v12.TypeMeta{},
			ListMeta: v12.ListMeta{},
			Items: []v1.Ingress{
				ingressExactPathMock,
			},
		},
		TlsCertificates: mocks.TlsCertificatesMock(),
		IngressLimiters: []*limiter.Limiter{ingressLimiter},
	}

	go func() {
		srv.Run(ctx)
	}()

	waitForServer(ctx, testReverseProxyConfig.Port)

	// check if user agent block works
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	t.Run("test user_agent curl/7.64.1 should not be blocked", func(t *testing.T) {
		req, err := http.NewRequest(
			"GET",
			fmt.Sprintf("https://%s:%d", testReverseProxyConfig.Host, testReverseProxyConfig.TlsPort),
			nil,
		)
		req.Header.Add("User-Agent", "curl/7.64.1")
		assert.NoError(t, err)
		req.Host = srv.RoutingTable.Ingresses.Items[0].Spec.Rules[0].Host

		res, err := http.DefaultClient.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, 200, res.StatusCode)
	})

	t.Run("test user_agent curl/7.64.2 should not be blocked", func(t *testing.T) {
		req, err := http.NewRequest(
			"GET",
			fmt.Sprintf("https://%s:%d", testReverseProxyConfig.Host, testReverseProxyConfig.TlsPort),
			nil,
		)
		req.Header.Add("User-Agent", "curl/7.64.2")
		assert.NoError(t, err)
		req.Host = srv.RoutingTable.Ingresses.Items[0].Spec.Rules[0].Host

		res, err := http.DefaultClient.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, 200, res.StatusCode)
	})

	t.Run("test user_agent curl/7.66.3 should be blocked", func(t *testing.T) {
		req, err := http.NewRequest(
			"GET",
			fmt.Sprintf("https://%s:%d", testReverseProxyConfig.Host, testReverseProxyConfig.TlsPort),
			nil,
		)
		req.Header.Add("User-Agent", "curl/7.66.3")
		assert.NoError(t, err)
		req.Host = srv.RoutingTable.Ingresses.Items[0].Spec.Rules[0].Host

		res, err := http.DefaultClient.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, 403, res.StatusCode)
	})
}

func TestRateLimitNotTriggeredOnWhitelistedPath(t *testing.T) {
	mockServerPort := freePort()
	numRequests := 10
	rateLimit := "1-S"
	mockServerAddress := fmt.Sprintf("127.0.0.1.default.svc.cluster.local:%d", mockServerPort)
	testReverseProxyConfig.Port = freePort()
	testReverseProxyConfig.TlsPort = freePort()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startMockServer(mockServerAddress, ctx)

	srv := New(testReverseProxyConfig)
	ingressExactPathMock := mocks.IngressExactPathTypeMock()
	ingressExactPathMock.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number = int32(mockServerPort)
	ingressExactPathMock.Spec.Rules[0].HTTP.Paths[0].Path = "/.well-known"
	ingressExactPathMock.Annotations = map[string]string{
		// rate limited after more than 10 requests per second
		"guardgress/limit-period": rateLimit,
		// whitelist healthz path
		"guardgress/limit-path-whitelist": "/foo,/.well-known",
	}
	ingressLimiterPathExact := limitHandler.GetIngressLimiter(ingressExactPathMock)

	srv.RoutingTable = &router.RoutingTable{
		Ingresses: &v1.IngressList{
			TypeMeta: v12.TypeMeta{},
			ListMeta: v12.ListMeta{},
			Items: []v1.Ingress{
				ingressExactPathMock,
			},
		},
		TlsCertificates: mocks.TlsCertificatesMock(),
		IngressLimiters: []*limiter.Limiter{ingressLimiterPathExact},
	}

	go func() {
		srv.Run(ctx)
	}()

	waitForServer(ctx, testReverseProxyConfig.Port)

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	t.Run("Rate limit should not be triggered on whitelisted path", func(t *testing.T) {
		req, err := http.NewRequest(
			"GET",
			fmt.Sprintf("https://%s:%d/.well-known", testReverseProxyConfig.Host, testReverseProxyConfig.TlsPort),
			nil,
		)
		assert.NoError(t, err)
		req.Host = srv.RoutingTable.Ingresses.Items[0].Spec.Rules[0].Host

		var wg sync.WaitGroup
		wg.Add(numRequests)

		// Simulating multiple requests concurrently
		for i := 0; i < (numRequests); i++ {
			go func(wg *sync.WaitGroup) {
				defer wg.Done()
				res, err := http.DefaultClient.Do(req)
				assert.NoError(t, err)
				assert.True(t, res.StatusCode != 429)
			}(&wg)
		}
		wg.Wait()
	})
}

func TestRateLimit10PerSecond(t *testing.T) {
	mockServerPort := freePort()
	requestLimit := 10
	mockServerAddress := fmt.Sprintf("127.0.0.1.default.svc.cluster.local:%d", mockServerPort)
	testReverseProxyConfig.Port = freePort()
	testReverseProxyConfig.TlsPort = freePort()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startMockServer(mockServerAddress, ctx)

	srv := New(testReverseProxyConfig)
	ingressExactPathMock := mocks.IngressExactPathTypeMock()
	ingressExactPathMock.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number = int32(mockServerPort)
	ingressExactPathMock.Spec.Rules[0].HTTP.Paths[0].Path = "/bar"
	ingressExactPathMock.Annotations = map[string]string{
		// rate limited after more than 10 requests per second
		"guardgress/limit-period": fmt.Sprintf("%d-S", requestLimit),
	}
	ingressLimiterPathExact := limitHandler.GetIngressLimiter(ingressExactPathMock)

	ingressPathPrefixMock := mocks.IngressPathTypePrefixMock()
	ingressPathPrefixMock.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number = int32(mockServerPort)
	ingressPathPrefixMock.Spec.Rules[0].HTTP.Paths[0].Path = "/foo"
	ingressPathPrefixMock.Annotations = map[string]string{}
	ingressLimiterPathPrefix := limitHandler.GetIngressLimiter(ingressExactPathMock)

	srv.RoutingTable = &router.RoutingTable{
		Ingresses: &v1.IngressList{
			TypeMeta: v12.TypeMeta{},
			ListMeta: v12.ListMeta{},
			Items: []v1.Ingress{
				ingressExactPathMock,
				ingressPathPrefixMock,
			},
		},
		TlsCertificates: mocks.TlsCertificatesMock(),
		IngressLimiters: []*limiter.Limiter{ingressLimiterPathExact, ingressLimiterPathPrefix},
	}

	go func() {
		srv.Run(ctx)
	}()

	waitForServer(ctx, testReverseProxyConfig.Port)

	// check if rate limit works
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	t.Run("test 10 simultaneously requests should not trigger rate limit (10S)", func(t *testing.T) {
		req, err := http.NewRequest(
			"GET",
			fmt.Sprintf("https://%s:%d/bar", testReverseProxyConfig.Host, testReverseProxyConfig.TlsPort),
			nil,
		)
		assert.NoError(t, err)
		req.Host = srv.RoutingTable.Ingresses.Items[0].Spec.Rules[0].Host

		var wg sync.WaitGroup
		wg.Add(requestLimit)

		// Simulating multiple requests concurrently
		for i := 0; i < requestLimit; i++ {
			go func(wg *sync.WaitGroup) {
				defer wg.Done()
				res, err := http.DefaultClient.Do(req)
				assert.NoError(t, err)
				assert.Equal(t, 200, res.StatusCode)
			}(&wg)
		}
		wg.Wait()

		res, err := http.DefaultClient.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, 429, res.StatusCode)
	})
}

func TestRateLimit60PerMinute(t *testing.T) {
	mockServerPort := freePort()
	requestLimit := 60
	mockServerAddress := fmt.Sprintf("127.0.0.1.default.svc.cluster.local:%d", mockServerPort)
	testReverseProxyConfig.Port = freePort()
	testReverseProxyConfig.TlsPort = freePort()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startMockServer(mockServerAddress, ctx)

	srv := New(testReverseProxyConfig)
	ingressExactPathMock := mocks.IngressExactPathTypeMock()
	ingressExactPathMock.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number = int32(mockServerPort)
	ingressExactPathMock.Spec.Rules[0].HTTP.Paths[0].Path = "/bar"
	ingressExactPathMock.Annotations = map[string]string{
		// rate limited after more than 60 requests per hour
		"guardgress/limit-period": fmt.Sprintf("%d-M", requestLimit),
	}
	ingressLimiterPathExact := limitHandler.GetIngressLimiter(ingressExactPathMock)

	ingressPathPrefixMock := mocks.IngressPathTypePrefixMock()
	ingressPathPrefixMock.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number = int32(mockServerPort)
	ingressPathPrefixMock.Spec.Rules[0].HTTP.Paths[0].Path = "/foo"
	ingressPathPrefixMock.Annotations = map[string]string{}
	ingressLimiterPathPrefix := limitHandler.GetIngressLimiter(ingressExactPathMock)

	srv.RoutingTable = &router.RoutingTable{
		Ingresses: &v1.IngressList{
			TypeMeta: v12.TypeMeta{},
			ListMeta: v12.ListMeta{},
			Items: []v1.Ingress{
				ingressExactPathMock,
				ingressPathPrefixMock,
			},
		},
		TlsCertificates: mocks.TlsCertificatesMock(),
		IngressLimiters: []*limiter.Limiter{ingressLimiterPathExact, ingressLimiterPathPrefix},
	}

	go func() {
		srv.Run(ctx)
	}()

	waitForServer(ctx, testReverseProxyConfig.Port)

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	t.Run("test 60 simultaneously requests should not trigger rate limit (60M)", func(t *testing.T) {
		req, err := http.NewRequest(
			"GET",
			fmt.Sprintf("https://%s:%d/bar", testReverseProxyConfig.Host, testReverseProxyConfig.TlsPort),
			nil,
		)
		assert.NoError(t, err)
		req.Host = srv.RoutingTable.Ingresses.Items[0].Spec.Rules[0].Host

		var wg sync.WaitGroup
		wg.Add(requestLimit)

		// Simulating multiple requests concurrently
		for i := 0; i < requestLimit; i++ {
			go func(wg *sync.WaitGroup) {
				defer wg.Done()
				res, err := http.DefaultClient.Do(req)
				assert.NoError(t, err)
				assert.Equal(t, 200, res.StatusCode)
			}(&wg)
		}
		wg.Wait()

		res, err := http.DefaultClient.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, 429, res.StatusCode)
	})
}

func TestRateLimit60PerHour(t *testing.T) {
	mockServerPort := freePort()
	requestLimit := 60
	mockServerAddress := fmt.Sprintf("127.0.0.1.default.svc.cluster.local:%d", mockServerPort)
	testReverseProxyConfig.Port = freePort()
	testReverseProxyConfig.TlsPort = freePort()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startMockServer(mockServerAddress, ctx)

	srv := New(testReverseProxyConfig)
	ingressExactPathMock := mocks.IngressExactPathTypeMock()
	ingressExactPathMock.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number = int32(mockServerPort)
	ingressExactPathMock.Spec.Rules[0].HTTP.Paths[0].Path = "/bar"
	ingressExactPathMock.Annotations = map[string]string{
		// rate limited after more than 60 requests per hour
		"guardgress/limit-period": fmt.Sprintf("%d-H", requestLimit),
	}
	ingressLimiterPathExact := limitHandler.GetIngressLimiter(ingressExactPathMock)

	ingressPathPrefixMock := mocks.IngressPathTypePrefixMock()
	ingressPathPrefixMock.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number = int32(mockServerPort)
	ingressPathPrefixMock.Spec.Rules[0].HTTP.Paths[0].Path = "/foo"
	ingressPathPrefixMock.Annotations = map[string]string{}
	ingressLimiterPathPrefix := limitHandler.GetIngressLimiter(ingressExactPathMock)

	srv.RoutingTable = &router.RoutingTable{
		Ingresses: &v1.IngressList{
			TypeMeta: v12.TypeMeta{},
			ListMeta: v12.ListMeta{},
			Items: []v1.Ingress{
				ingressExactPathMock,
				ingressPathPrefixMock,
			},
		},
		TlsCertificates: mocks.TlsCertificatesMock(),
		IngressLimiters: []*limiter.Limiter{ingressLimiterPathExact, ingressLimiterPathPrefix},
	}

	go func() {
		srv.Run(ctx)
	}()

	waitForServer(ctx, testReverseProxyConfig.Port)

	// check if rate limit works
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	t.Run("test 60 simultaneously requests should not trigger rate limit (60H)", func(t *testing.T) {
		req, err := http.NewRequest(
			"GET",
			fmt.Sprintf("https://%s:%d/bar", testReverseProxyConfig.Host, testReverseProxyConfig.TlsPort),
			nil,
		)
		assert.NoError(t, err)
		req.Host = srv.RoutingTable.Ingresses.Items[0].Spec.Rules[0].Host

		var wg sync.WaitGroup
		wg.Add(requestLimit)

		// Simulating multiple requests concurrently
		for i := 0; i < requestLimit; i++ {
			go func(wg *sync.WaitGroup) {
				defer wg.Done()
				res, err := http.DefaultClient.Do(req)
				assert.NoError(t, err)
				assert.Equal(t, 200, res.StatusCode)
			}(&wg)
		}
		wg.Wait()

		res, err := http.DefaultClient.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, 429, res.StatusCode)
	})
}

func TestPathRoutingWithMultipleIngressesAndNamespaces(t *testing.T) {
	mockServerPort := freePort()
	mockServerAddress := fmt.Sprintf("127.0.0.1.default.svc.cluster.local:%d", mockServerPort)
	testReverseProxyConfig.Port = freePort()
	testReverseProxyConfig.TlsPort = freePort()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startMockServer(mockServerAddress, ctx)

	srv := New(testReverseProxyConfig)

	ingressExactPathMock := mocks.IngressExactPathTypeMock()
	ingressExactPathMock.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number = int32(mockServerPort)
	ingressExactPathMock.Spec.Rules[0].HTTP.Paths[0].Path = "/bar"
	ingressExactPathMock.Annotations = map[string]string{
		"guardgress/user-agent-whitelist": "curl/7.64.*",
		"guardgress/user-agent-blacklist": "curl/7.64.*,curl/7.65.*",
	}
	ingressExactPathMock.Namespace = "test"
	ingressLimiterPathExact := limitHandler.GetIngressLimiter(ingressExactPathMock)

	ingressPathPrefixMock := mocks.IngressPathTypePrefixMock()
	ingressPathPrefixMock.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number = int32(mockServerPort)
	ingressPathPrefixMock.Spec.Rules[0].HTTP.Paths[0].Path = "/foo"
	ingressPathPrefixMock.Annotations = map[string]string{}
	ingressExactPathMock.Namespace = "test"
	ingressLimiterPathPrefix := limitHandler.GetIngressLimiter(ingressExactPathMock)

	srv.RoutingTable = &router.RoutingTable{
		Ingresses: &v1.IngressList{
			TypeMeta: v12.TypeMeta{},
			ListMeta: v12.ListMeta{},
			Items: []v1.Ingress{
				ingressExactPathMock,
				ingressPathPrefixMock,
			},
		},
		TlsCertificates: mocks.TlsCertificatesMock(),
		IngressLimiters: []*limiter.Limiter{ingressLimiterPathExact, ingressLimiterPathPrefix},
	}

	go func() {
		srv.Run(ctx)
	}()

	waitForServer(ctx, testReverseProxyConfig.Port)

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	t.Run("test if user agent block works with multiple ingresses (curl/7.64.1 should work)", func(t *testing.T) {
		req, err := http.NewRequest(
			"GET",
			fmt.Sprintf("https://%s:%d/bar", testReverseProxyConfig.Host, testReverseProxyConfig.TlsPort),
			nil,
		)
		req.Header.Add("User-Agent", "curl/7.64.1")
		assert.NoError(t, err)
		req.Host = srv.RoutingTable.Ingresses.Items[0].Spec.Rules[0].Host

		res, err := http.DefaultClient.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, 200, res.StatusCode)
	})

	t.Run("test if user agent block works with multiple ingresses (curl/7.64.2 should work)", func(t *testing.T) {
		req, err := http.NewRequest(
			"GET",
			fmt.Sprintf("https://%s:%d/bar", testReverseProxyConfig.Host, testReverseProxyConfig.TlsPort),
			nil,
		)
		req.Header.Add("User-Agent", "curl/7.64.2")
		assert.NoError(t, err)
		req.Host = srv.RoutingTable.Ingresses.Items[0].Spec.Rules[0].Host

		res, err := http.DefaultClient.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, 200, res.StatusCode)
	})

	t.Run("test if user agent block works with multiple ingresses (curl/7.66.3 should not work)", func(t *testing.T) {
		req, err := http.NewRequest(
			"GET",
			fmt.Sprintf("https://%s:%d/bar", testReverseProxyConfig.Host, testReverseProxyConfig.TlsPort),
			nil,
		)
		req.Header.Add("User-Agent", "curl/7.66.3")
		assert.NoError(t, err)
		req.Host = srv.RoutingTable.Ingresses.Items[0].Spec.Rules[0].Host

		res, err := http.DefaultClient.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, 403, res.StatusCode)
	})

	t.Run("test if user agent works on ingress without the block annotation /foo (curl/7.64.1 should work)", func(t *testing.T) {
		req, err := http.NewRequest(
			"GET",
			fmt.Sprintf("https://%s:%d/foo", testReverseProxyConfig.Host, testReverseProxyConfig.TlsPort),
			nil,
		)
		req.Header.Add("User-Agent", "curl/7.64.1")
		assert.NoError(t, err)
		req.Host = srv.RoutingTable.Ingresses.Items[0].Spec.Rules[0].Host

		res, err := http.DefaultClient.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, 200, res.StatusCode)
	})

	t.Run("test if user agent works on ingress without the block annotation /foo/bar (curl/7.64.2 should work)", func(t *testing.T) {
		req, err := http.NewRequest(
			"GET",
			fmt.Sprintf("https://%s:%d/foo/bar", testReverseProxyConfig.Host, testReverseProxyConfig.TlsPort),
			nil,
		)
		req.Header.Add("User-Agent", "curl/7.64.2")
		assert.NoError(t, err)
		req.Host = srv.RoutingTable.Ingresses.Items[0].Spec.Rules[0].Host

		res, err := http.DefaultClient.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, 200, res.StatusCode)
	})

	t.Run("test if user agent works on ingress without the block annotation /foo/bar/../bar/bar (curl/7.64.3 should work)", func(t *testing.T) {
		req, err := http.NewRequest(
			"GET",
			fmt.Sprintf("https://%s:%d/foo/bar/../bar/bar", testReverseProxyConfig.Host, testReverseProxyConfig.TlsPort),
			nil,
		)
		req.Header.Add("User-Agent", "curl/7.64.3")
		assert.NoError(t, err)
		req.Host = srv.RoutingTable.Ingresses.Items[0].Spec.Rules[0].Host

		res, err := http.DefaultClient.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, 200, res.StatusCode)
	})
}

func TestSetLogLevel(t *testing.T) {
	logLevel, ok := os.LookupEnv("LOG_LEVEL")
	assert.False(t, ok)

	_ = os.Setenv("LOG_LEVEL", "debug")
	logLevel, _ = os.LookupEnv("LOG_LEVEL")
	level, err := log.ParseLevel(logLevel)
	assert.NoError(t, err)
	log.SetLevel(level)
	assert.Equal(t, log.GetLevel(), log.DebugLevel)

	_ = os.Setenv("LOG_LEVEL", "info")
	logLevel, _ = os.LookupEnv("LOG_LEVEL")
	level, err = log.ParseLevel(logLevel)
	assert.NoError(t, err)
	log.SetLevel(level)
	assert.Equal(t, log.GetLevel(), log.InfoLevel)
}

func TestHealthzRoute(t *testing.T) {
	mockServerPort := freePort()
	mockServerAddress := fmt.Sprintf("127.0.0.1.default.svc.cluster.local:%d", mockServerPort)
	testReverseProxyConfig.Port = freePort()
	testReverseProxyConfig.TlsPort = freePort()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startMockServer(mockServerAddress, ctx)

	srv := New(testReverseProxyConfig)

	srv.RoutingTable = &router.RoutingTable{
		Ingresses: &v1.IngressList{
			TypeMeta: v12.TypeMeta{},
			ListMeta: v12.ListMeta{},
			Items:    []v1.Ingress{},
		},
		TlsCertificates: mocks.TlsCertificatesMock(),
		IngressLimiters: []*limiter.Limiter{},
	}

	go func() {
		srv.Run(ctx)
	}()

	waitForServer(ctx, testReverseProxyConfig.Port)

	t.Run("test healthz route", func(t *testing.T) {
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		req, err := http.NewRequest(
			"GET",
			fmt.Sprintf("https://%s:%d/healthz", testReverseProxyConfig.Host, testReverseProxyConfig.TlsPort),
			nil,
		)
		assert.NoError(t, err)
		res, err := http.DefaultClient.Do(req)
		assert.NoError(t, err)
		// should not return 404
		assert.Equal(t, 200, res.StatusCode)
		bs, err := io.ReadAll(res.Body)
		assert.Equal(t, string(bs), "ok")
	})
}

func TestProxyDirectorParams(t *testing.T) {
	mockServerPort := freePort()
	mockServerAddress := fmt.Sprintf("127.0.0.1.default.svc.cluster.local:%d", mockServerPort)
	testReverseProxyConfig.Port = freePort()
	testReverseProxyConfig.TlsPort = freePort()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ingressExactPathMock := mocks.IngressExactPathTypeMock()
	ingressExactPathMock.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number = int32(mockServerPort)
	ingressExactPathMock.Spec.Rules[0].HTTP.Paths[0].Path = "/bar"
	ingressExactPathMock.Spec.Rules[0].Host = "www.guardgress.com"
	ingressLimiterPathExact := limitHandler.GetIngressLimiter(ingressExactPathMock)

	startMockServer(mockServerAddress, ctx)

	srv := New(testReverseProxyConfig)

	srv.RoutingTable = &router.RoutingTable{
		Ingresses: &v1.IngressList{
			TypeMeta: v12.TypeMeta{},
			ListMeta: v12.ListMeta{},
			Items: []v1.Ingress{
				ingressExactPathMock,
			},
		},
		TlsCertificates: mocks.TlsCertificatesMock(),
		IngressLimiters: []*limiter.Limiter{ingressLimiterPathExact},
	}

	go func() {
		srv.Run(ctx)
	}()

	waitForServer(ctx, testReverseProxyConfig.Port)

	t.Run("test proxy director params", func(t *testing.T) {
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		req, err := http.NewRequest(
			"GET",
			fmt.Sprintf("https://%s:%d/bar", testReverseProxyConfig.Host, testReverseProxyConfig.TlsPort),
			nil,
		)
		req.Host = ingressExactPathMock.Spec.Rules[0].Host
		assert.NoError(t, err)
		res, err := http.DefaultClient.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, 200, res.StatusCode)
		bs, err := io.ReadAll(res.Body)
		assert.Equal(t, mockServerResponse, string(bs))
		// host header is important for proxy director
		assert.Equal(t, res.Header.Get("X-Requested-With-Host"), ingressExactPathMock.Spec.Rules[0].Host)
	})
}

func TestHTTPToHTTPSRedirect(t *testing.T) {
	mockServerPort := freePort()
	mockServerAddress := fmt.Sprintf("127.0.0.1.default.svc.cluster.local:%d", mockServerPort)
	testReverseProxyConfig.Port = freePort()
	testReverseProxyConfig.TlsPort = freePort()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startMockServer(mockServerAddress, ctx)

	srv := New(testReverseProxyConfig)

	ingressExactPathMock := mocks.IngressExactPathTypeMock()
	ingressExactPathMock.Annotations = map[string]string{
		"guardgress/force-ssl-redirect": "true",
	}
	ingressExactPathMock.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number = int32(mockServerPort)
	ingressLimiter := limitHandler.GetIngressLimiter(ingressExactPathMock)

	srv.RoutingTable = &router.RoutingTable{
		Ingresses: &v1.IngressList{
			TypeMeta: v12.TypeMeta{},
			ListMeta: v12.ListMeta{},
			Items: []v1.Ingress{
				ingressExactPathMock,
			},
		},
		TlsCertificates: mocks.TlsCertificatesMock(),
		IngressLimiters: []*limiter.Limiter{ingressLimiter},
	}

	go func() {
		srv.Run(ctx)
	}()

	waitForServer(ctx, testReverseProxyConfig.Port)

	// check if https redirect works
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	req, err := http.NewRequest(
		"GET",
		fmt.Sprintf("http://%s:%d", testReverseProxyConfig.Host, testReverseProxyConfig.Port),
		nil,
	)
	assert.NoError(t, err)
	req.Host = srv.RoutingTable.Ingresses.Items[0].Spec.Rules[0].Host

	_, err = http.DefaultClient.Do(req)
	// Error is expected. Just check if https redirect worked
	assert.True(t, strings.ContainsAny("https://127.0.0.1", err.Error()))
}

func startMockServer(addr string, ctx context.Context) *http.Server {
	mockSrv := &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, v := range []string{"X-Ja3-Fingerprint", "X-Ja4-Fingerprint"} {
				if ok := r.Header.Get(v); ok != "" {
					w.Header().Set(v, r.Header.Get(v))
				}
			}
			w.Header().Set("X-Requested-With-Host", r.Host)
			_, _ = io.WriteString(w, mockServerResponse)
		}),
	}
	go func() {
		<-ctx.Done()
		_ = mockSrv.Close()
	}()
	go func() {
		err := mockSrv.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("Mock server error: %s", err)
		}
	}()
	return mockSrv
}

func waitForServer(ctx context.Context, port int) bool {
	ctx, cleanup := context.WithTimeout(ctx, time.Second*10)
	defer cleanup()

	ticker := time.NewTicker(time.Millisecond * 50)
	defer ticker.Stop()

	for range ticker.C {
		select {
		case <-ctx.Done():
			return false
		default:
		}

		if conn, err := net.Dial("tcp4", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
			_ = conn.Close()
			return true
		}
	}
	panic("impossible")
}

func freePort() int {
	// Listen on a random port
	listener, _ := net.Listen("tcp", ":0")
	defer func(listener net.Listener) {
		err := listener.Close()
		if err != nil {
			log.Error(err)
		}
	}(listener)

	// Retrieve the address information
	address := listener.Addr().(*net.TCPAddr)
	return address.Port
}
