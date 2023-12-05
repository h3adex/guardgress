package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/h3adex/guardgress/pkg/limitHandler"
	"github.com/h3adex/guardgress/pkg/mocks"
	"github.com/h3adex/guardgress/pkg/router"
	"github.com/stretchr/testify/assert"
	"github.com/ulule/limiter/v3"
	"io"
	v1 "k8s.io/api/networking/v1"
	v12 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"log"
	"net"
	"net/http"
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

func TestHTTPRequest(t *testing.T) {
	mockServerPort := freePort()
	mockServerAddress := fmt.Sprintf("127.0.0.1:%d", mockServerPort)
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

	waitForServer(ctx, 10101)

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
	mockServerAddress := fmt.Sprintf("127.0.0.1:%d", mockServerPort)
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
	mockServerAddress := fmt.Sprintf("127.0.0.1:%d", mockServerPort)
	testReverseProxyConfig.Port = freePort()
	testReverseProxyConfig.TlsPort = freePort()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startMockServer(mockServerAddress, ctx)

	srv := New(testReverseProxyConfig)

	ingressExactPathMock := mocks.IngressExactPathTypeMock()
	ingressExactPathMock.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number = int32(mockServerPort)
	ingressExactPathMock.Annotations = map[string]string{
		"guardgress/add-ja3-header": "true",
		"guardgress/add-ja4-header": "true",
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

	waitForServer(ctx, 10101)

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
	assert.Equal(t, len(res.Header.Get("X-Ja3-Fingerprint")) > 1, true)
	assert.Equal(t, len(res.Header.Get("X-Ja4-Fingerprint")) > 1, true)
}

func TestUserAgentBlacklist(t *testing.T) {
	mockServerPort := freePort()
	mockServerAddress := fmt.Sprintf("127.0.0.1:%d", mockServerPort)
	testReverseProxyConfig.Port = freePort()
	testReverseProxyConfig.TlsPort = freePort()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startMockServer(mockServerAddress, ctx)

	srv := New(testReverseProxyConfig)

	ingressExactPathMock := mocks.IngressExactPathTypeMock()
	ingressExactPathMock.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number = int32(mockServerPort)
	ingressExactPathMock.Annotations = map[string]string{
		"guardgress/user-agent-blacklist": "curl/7.64.1,curl/7.64.2",
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

	waitForServer(ctx, 10101)

	// check if user agent block works
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	// should not work
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

	// should not work
	req, err = http.NewRequest(
		"GET",
		fmt.Sprintf("https://%s:%d", testReverseProxyConfig.Host, testReverseProxyConfig.TlsPort),
		nil,
	)
	req.Header.Add("User-Agent", "curl/7.64.2")
	assert.NoError(t, err)
	req.Host = srv.RoutingTable.Ingresses.Items[0].Spec.Rules[0].Host

	res, err = http.DefaultClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 403, res.StatusCode)

	// should work
	req, err = http.NewRequest(
		"GET",
		fmt.Sprintf("https://%s:%d", testReverseProxyConfig.Host, testReverseProxyConfig.TlsPort),
		nil,
	)
	req.Header.Add("User-Agent", "curl/7.64.3")
	assert.NoError(t, err)
	req.Host = srv.RoutingTable.Ingresses.Items[0].Spec.Rules[0].Host

	res, err = http.DefaultClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)
}

func TestRateLimit10PerSecond(t *testing.T) {
	mockServerPort := freePort()
	requestLimit := 10
	mockServerAddress := fmt.Sprintf("127.0.0.1:%d", mockServerPort)
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

	waitForServer(ctx, 10101)

	// check if rate limit works
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	// should not work
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
}

func TestRateLimit60PerMinute(t *testing.T) {
	mockServerPort := freePort()
	requestLimit := 60
	mockServerAddress := fmt.Sprintf("127.0.0.1:%d", mockServerPort)
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

	waitForServer(ctx, 10101)

	// check if rate limit works
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	// should not work
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
}

func TestRateLimit60PerHour(t *testing.T) {
	mockServerPort := freePort()
	requestLimit := 60
	mockServerAddress := fmt.Sprintf("127.0.0.1:%d", mockServerPort)
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

	waitForServer(ctx, 10101)

	// check if rate limit works
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	// should not work
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
}

func TestPathRoutingWithMultipleIngresses(t *testing.T) {
	mockServerPort := freePort()
	mockServerAddress := fmt.Sprintf("127.0.0.1:%d", mockServerPort)
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
		"guardgress/user-agent-blacklist": "curl/7.64.1,curl/7.64.2",
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

	waitForServer(ctx, 10101)

	// check if user agent block works
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	// should not work
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
	assert.Equal(t, 403, res.StatusCode)

	// should not work
	req, err = http.NewRequest(
		"GET",
		fmt.Sprintf("https://%s:%d/bar", testReverseProxyConfig.Host, testReverseProxyConfig.TlsPort),
		nil,
	)
	req.Header.Add("User-Agent", "curl/7.64.2")
	assert.NoError(t, err)
	req.Host = srv.RoutingTable.Ingresses.Items[0].Spec.Rules[0].Host

	res, err = http.DefaultClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 403, res.StatusCode)

	// should work
	req, err = http.NewRequest(
		"GET",
		fmt.Sprintf("https://%s:%d/bar", testReverseProxyConfig.Host, testReverseProxyConfig.TlsPort),
		nil,
	)
	req.Header.Add("User-Agent", "curl/7.64.3")
	assert.NoError(t, err)
	req.Host = srv.RoutingTable.Ingresses.Items[0].Spec.Rules[0].Host

	res, err = http.DefaultClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)

	// should work since the user agent block annotation is not set on this ingress object
	req, err = http.NewRequest(
		"GET",
		fmt.Sprintf("https://%s:%d/foo", testReverseProxyConfig.Host, testReverseProxyConfig.TlsPort),
		nil,
	)
	req.Header.Add("User-Agent", "curl/7.64.1")
	assert.NoError(t, err)
	req.Host = srv.RoutingTable.Ingresses.Items[0].Spec.Rules[0].Host

	res, err = http.DefaultClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)

	// should work since the user agent block annotation is not set on this ingress object
	req, err = http.NewRequest(
		"GET",
		fmt.Sprintf("https://%s:%d/foo/bar", testReverseProxyConfig.Host, testReverseProxyConfig.TlsPort),
		nil,
	)
	req.Header.Add("User-Agent", "curl/7.64.2")
	assert.NoError(t, err)
	req.Host = srv.RoutingTable.Ingresses.Items[0].Spec.Rules[0].Host

	res, err = http.DefaultClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)

	// should work since the user agent block annotation is not set on this ingress object
	req, err = http.NewRequest(
		"GET",
		fmt.Sprintf("https://%s:%d/foo/bar/../bar/bar", testReverseProxyConfig.Host, testReverseProxyConfig.TlsPort),
		nil,
	)
	req.Header.Add("User-Agent", "curl/7.64.3")
	assert.NoError(t, err)
	req.Host = srv.RoutingTable.Ingresses.Items[0].Spec.Rules[0].Host

	res, err = http.DefaultClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)
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
	defer listener.Close()

	// Retrieve the address information
	address := listener.Addr().(*net.TCPAddr)
	return address.Port
}
