// If you want to run this tests you have to edit your /etc/hosts file and add the following line:
// 127.0.0.1 127.0.0.1.default.svc.cluster.local
// 127.0.0.1 127.0.0.1.test.svc.cluster.local
// TODO: is the a better way to do this? Editing /etc/hosts might no be possible in some environments.
package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/h3adex/guardgress/pkg/healthmetrics"
	"github.com/h3adex/guardgress/pkg/limithandler"
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
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

var mockServerResponse = "mock-svc"

type MockServerConfig struct {
	Host string
	Port int
}

func init() {
	log.SetLevel(log.InfoLevel)

	if log.GetLevel() != log.DebugLevel {
		gin.SetMode(gin.ReleaseMode)
	}
}

func TestHTTPRequest(t *testing.T) {
	reverseProxyConfig := &Config{Host: "127.0.0.1", Port: freePort(), TlsPort: freePort()}
	mockServerConfig := &MockServerConfig{Host: "127.0.0.1.default.svc.cluster.local", Port: freePort()}
	ctx := context.Background()

	runMockServer(fmt.Sprintf("%s:%d", mockServerConfig.Host, mockServerConfig.Port), ctx)
	srv := New(reverseProxyConfig)

	ingressExactPathMock := mocks.IngressExactPathTypeMock()
	ingressExactPathMock.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number = int32(mockServerConfig.Port)
	ingressLimiter := limithandler.GetIngressLimiter(ingressExactPathMock)

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
		err := srv.Run(ctx)
		assert.NoError(t, err)
	}()

	go func() {
		err := os.Setenv("HEALTH_METRICS_PORT", strconv.Itoa(freePort()))
		assert.NoError(t, err)
		err = healthmetrics.New().Run(ctx)
		assert.NoError(t, err)
	}()

	waitForServer(ctx, reverseProxyConfig.Port)

	// check if reverse proxy works for http request
	t.Run("test if reverse proxy works for http request", func(t *testing.T) {
		req, err := http.NewRequest(
			"GET",
			fmt.Sprintf("http://%s:%d", reverseProxyConfig.Host, reverseProxyConfig.Port),
			nil,
		)
		assert.NoError(t, err)
		req.Host = srv.RoutingTable.Ingresses.Items[0].Spec.Rules[0].Host

		res, err := http.DefaultClient.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, 200, res.StatusCode)
		bs, err := io.ReadAll(res.Body)
		assert.NoError(t, err)
		err = res.Body.Close()
		assert.NoError(t, err)
		assert.Equal(t, mockServerResponse, string(bs))
	})
}

func TestHTTPSRequest(t *testing.T) {
	reverseProxyConfig := &Config{Host: "127.0.0.1", Port: freePort(), TlsPort: freePort()}
	mockServerConfig := &MockServerConfig{Host: "127.0.0.1.default.svc.cluster.local", Port: freePort()}
	ctx := context.Background()

	runMockServer(fmt.Sprintf("%s:%d", mockServerConfig.Host, mockServerConfig.Port), ctx)
	srv := New(reverseProxyConfig)

	ingressExactPathMock := mocks.IngressExactPathTypeMock()
	ingressExactPathMock.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number = int32(mockServerConfig.Port)
	ingressLimiter := limithandler.GetIngressLimiter(ingressExactPathMock)

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
		_ = srv.Run(ctx)
	}()

	go func() {
		err := os.Setenv("HEALTH_METRICS_PORT", strconv.Itoa(freePort()))
		assert.NoError(t, err)
		err = healthmetrics.New().Run(ctx)
		assert.NoError(t, err)
	}()

	waitForServer(ctx, reverseProxyConfig.Port)

	t.Run("test if reverse proxy works for https request", func(t *testing.T) {
		// check if reverse proxy works for https request
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		req, err := http.NewRequest(
			"GET",
			fmt.Sprintf("https://%s:%d", reverseProxyConfig.Host, reverseProxyConfig.TlsPort),
			nil,
		)
		assert.NoError(t, err)
		req.Host = srv.RoutingTable.Ingresses.Items[0].Spec.Rules[0].Host

		res, err := http.DefaultClient.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, 200, res.StatusCode)
		bs, err := io.ReadAll(res.Body)
		assert.NoError(t, err)
		err = res.Body.Close()
		assert.NoError(t, err)
		assert.Equal(t, mockServerResponse, string(bs))

		// check if metrics are working
		/*		res, err = http.Get(fmt.Sprintf("http://%s/metrics", healthMetricsServerAddress))
				assert.NoError(t, err)
				assert.Equal(t, 200, res.StatusCode)
				bs, err = io.ReadAll(res.Body)
				assert.NoError(t, err)
				assert.True(t, strings.ContainsAny(string(bs), "http_https_request_status_code_count{protocol=\"https\""))*/
	})
}

func TestTlsFingerprintingAddHeader(t *testing.T) {
	reverseProxyConfig := &Config{Host: "127.0.0.1", Port: freePort(), TlsPort: freePort()}
	mockServerConfig := &MockServerConfig{Host: "127.0.0.1.default.svc.cluster.local", Port: freePort()}
	ctx := context.Background()

	runMockServer(fmt.Sprintf("%s:%d", mockServerConfig.Host, mockServerConfig.Port), ctx)
	srv := New(reverseProxyConfig)

	ingressExactPathMock := mocks.IngressExactPathTypeMock()
	ingressExactPathMock.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number = int32(mockServerConfig.Port)
	ingressExactPathMock.Annotations = map[string]string{"guardgress/add-tls-fingerprint-header": "true"}
	ingressLimiter := limithandler.GetIngressLimiter(ingressExactPathMock)

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
		_ = srv.Run(ctx)
	}()

	go func() {
		err := os.Setenv("HEALTH_METRICS_PORT", strconv.Itoa(freePort()))
		assert.NoError(t, err)
		err = healthmetrics.New().Run(ctx)
		assert.NoError(t, err)
	}()

	waitForServer(ctx, reverseProxyConfig.Port)

	// check if reverse proxy returns tls fingerprints
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	req, err := http.NewRequest(
		"GET",
		fmt.Sprintf("https://%s:%d", reverseProxyConfig.Host, reverseProxyConfig.TlsPort),
		nil,
	)
	assert.NoError(t, err)
	req.Host = srv.RoutingTable.Ingresses.Items[0].Spec.Rules[0].Host

	res, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)
	assert.NoError(t, err)
	err = res.Body.Close()
	assert.NoError(t, err)

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
	assert.NoError(t, err)
	assert.Equal(t, 403, res.StatusCode)
}

func TestUserAgentBlacklist(t *testing.T) {
	reverseProxyConfig := &Config{Host: "127.0.0.1", Port: freePort(), TlsPort: freePort()}
	mockServerConfig := &MockServerConfig{Host: "127.0.0.1.default.svc.cluster.local", Port: freePort()}
	ctx := context.Background()

	runMockServer(fmt.Sprintf("%s:%d", mockServerConfig.Host, mockServerConfig.Port), ctx)
	srv := New(reverseProxyConfig)

	ingressExactPathMock := mocks.IngressExactPathTypeMock()
	ingressExactPathMock.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number = int32(mockServerConfig.Port)
	ingressExactPathMock.Annotations = map[string]string{
		"guardgress/user-agent-blacklist": "curl/7.64.*,curl/7.65.*",
	}
	ingressLimiter := limithandler.GetIngressLimiter(ingressExactPathMock)

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
		_ = srv.Run(ctx)
	}()

	go func() {
		err := os.Setenv("HEALTH_METRICS_PORT", strconv.Itoa(freePort()))
		assert.NoError(t, err)
		err = healthmetrics.New().Run(ctx)
		assert.NoError(t, err)
	}()

	waitForServer(ctx, reverseProxyConfig.Port)

	// check if user agent block works
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	for _, url := range []string{
		fmt.Sprintf("https://%s:%d", reverseProxyConfig.Host, reverseProxyConfig.TlsPort),
		fmt.Sprintf("http://%s:%d", reverseProxyConfig.Host, reverseProxyConfig.Port),
	} {
		req, err := http.NewRequest(
			"GET",
			url,
			nil,
		)
		req.Header.Add("User-Agent", "curl/7.64.1")
		assert.NoError(t, err)
		req.Host = srv.RoutingTable.Ingresses.Items[0].Spec.Rules[0].Host

		res, err := http.DefaultClient.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, 403, res.StatusCode)
	}

	t.Run("test user_agent curl/7.64.1 should be blocked", func(t *testing.T) {
		for _, url := range []string{
			fmt.Sprintf("https://%s:%d", reverseProxyConfig.Host, reverseProxyConfig.TlsPort),
			fmt.Sprintf("http://%s:%d", reverseProxyConfig.Host, reverseProxyConfig.Port),
		} {
			req, err := http.NewRequest(
				"GET",
				url,
				nil,
			)
			req.Header.Add("User-Agent", "curl/7.64.1")
			assert.NoError(t, err)
			req.Host = srv.RoutingTable.Ingresses.Items[0].Spec.Rules[0].Host

			res, err := http.DefaultClient.Do(req)
			assert.NoError(t, err)
			assert.Equal(t, 403, res.StatusCode)
		}
	})

	t.Run("test user_agent curl/7.64.2 should be blocked", func(t *testing.T) {
		for _, url := range []string{
			fmt.Sprintf("https://%s:%d", reverseProxyConfig.Host, reverseProxyConfig.TlsPort),
			fmt.Sprintf("http://%s:%d", reverseProxyConfig.Host, reverseProxyConfig.Port),
		} {
			req, err := http.NewRequest(
				"GET",
				url,
				nil,
			)
			req.Header.Add("User-Agent", "curl/7.64.2")
			assert.NoError(t, err)
			req.Host = srv.RoutingTable.Ingresses.Items[0].Spec.Rules[0].Host

			res, err := http.DefaultClient.Do(req)
			assert.NoError(t, err)
			assert.Equal(t, 403, res.StatusCode)
		}
	})

	t.Run("test user_agent curl/7.66.3 should not be blocked", func(t *testing.T) {
		for _, url := range []string{
			fmt.Sprintf("https://%s:%d", reverseProxyConfig.Host, reverseProxyConfig.TlsPort),
			fmt.Sprintf("http://%s:%d", reverseProxyConfig.Host, reverseProxyConfig.Port),
		} {
			req, err := http.NewRequest(
				"GET",
				url,
				nil,
			)
			req.Header.Add("User-Agent", "curl/7.66.3")
			assert.NoError(t, err)
			req.Host = srv.RoutingTable.Ingresses.Items[0].Spec.Rules[0].Host

			res, err := http.DefaultClient.Do(req)
			assert.NoError(t, err)
			assert.Equal(t, 200, res.StatusCode)
		}
	})
}

func TestUserAgentWhitelist(t *testing.T) {
	reverseProxyConfig := &Config{Host: "127.0.0.1", Port: freePort(), TlsPort: freePort()}
	mockServerConfig := &MockServerConfig{Host: "127.0.0.1.default.svc.cluster.local", Port: freePort()}
	ctx := context.Background()

	runMockServer(fmt.Sprintf("%s:%d", mockServerConfig.Host, mockServerConfig.Port), ctx)
	srv := New(reverseProxyConfig)

	ingressExactPathMock := mocks.IngressExactPathTypeMock()
	ingressExactPathMock.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number = int32(mockServerConfig.Port)
	ingressExactPathMock.Annotations = map[string]string{
		"guardgress/user-agent-whitelist": "curl/7.64.*,curl/7.65.*",
	}
	ingressLimiter := limithandler.GetIngressLimiter(ingressExactPathMock)

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
		_ = srv.Run(ctx)
	}()

	waitForServer(ctx, reverseProxyConfig.Port)

	// check if user agent block works
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	t.Run("test user_agent curl/7.64.1 should not be blocked", func(t *testing.T) {
		for _, url := range []string{
			fmt.Sprintf("https://%s:%d", reverseProxyConfig.Host, reverseProxyConfig.TlsPort),
			fmt.Sprintf("http://%s:%d", reverseProxyConfig.Host, reverseProxyConfig.Port),
		} {
			req, err := http.NewRequest(
				"GET",
				url,
				nil,
			)
			req.Header.Add("User-Agent", "curl/7.64.1")
			assert.NoError(t, err)
			req.Host = srv.RoutingTable.Ingresses.Items[0].Spec.Rules[0].Host

			res, err := http.DefaultClient.Do(req)
			assert.NoError(t, err)
			assert.Equal(t, 200, res.StatusCode)
		}
	})

	t.Run("test user_agent curl/7.64.2 should not be blocked", func(t *testing.T) {
		for _, url := range []string{
			fmt.Sprintf("https://%s:%d", reverseProxyConfig.Host, reverseProxyConfig.TlsPort),
			fmt.Sprintf("http://%s:%d", reverseProxyConfig.Host, reverseProxyConfig.Port),
		} {
			req, err := http.NewRequest(
				"GET",
				url,
				nil,
			)
			req.Header.Add("User-Agent", "curl/7.64.2")
			assert.NoError(t, err)
			req.Host = srv.RoutingTable.Ingresses.Items[0].Spec.Rules[0].Host

			res, err := http.DefaultClient.Do(req)
			assert.NoError(t, err)
			assert.Equal(t, 200, res.StatusCode)
		}
	})

	t.Run("test user_agent curl/7.66.3 should be blocked", func(t *testing.T) {
		for _, url := range []string{
			fmt.Sprintf("https://%s:%d", reverseProxyConfig.Host, reverseProxyConfig.TlsPort),
			fmt.Sprintf("http://%s:%d", reverseProxyConfig.Host, reverseProxyConfig.Port),
		} {
			req, err := http.NewRequest(
				"GET",
				url,
				nil,
			)
			req.Header.Add("User-Agent", "curl/7.66.3")
			assert.NoError(t, err)
			req.Host = srv.RoutingTable.Ingresses.Items[0].Spec.Rules[0].Host

			res, err := http.DefaultClient.Do(req)
			assert.NoError(t, err)
			assert.Equal(t, 403, res.StatusCode)
		}
	})
}

func TestUserAgentBlackAndWhitelist(t *testing.T) {
	reverseProxyConfig := &Config{Host: "127.0.0.1", Port: freePort(), TlsPort: freePort()}
	mockServerConfig := &MockServerConfig{Host: "127.0.0.1.default.svc.cluster.local", Port: freePort()}
	ctx := context.Background()

	runMockServer(fmt.Sprintf("%s:%d", mockServerConfig.Host, mockServerConfig.Port), ctx)
	srv := New(reverseProxyConfig)

	ingressExactPathMock := mocks.IngressExactPathTypeMock()
	ingressExactPathMock.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number = int32(mockServerConfig.Port)
	ingressExactPathMock.Annotations = map[string]string{
		"guardgress/user-agent-whitelist": "curl/7.64.*",
		"guardgress/user-agent-blacklist": "curl/7.64.*,curl/7.65.*",
	}
	ingressLimiter := limithandler.GetIngressLimiter(ingressExactPathMock)

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
		_ = srv.Run(ctx)
	}()

	waitForServer(ctx, reverseProxyConfig.Port)

	// check if user agent block works
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	t.Run("test user_agent curl/7.64.1 should not be blocked", func(t *testing.T) {
		for _, url := range []string{
			fmt.Sprintf("https://%s:%d", reverseProxyConfig.Host, reverseProxyConfig.TlsPort),
			fmt.Sprintf("http://%s:%d", reverseProxyConfig.Host, reverseProxyConfig.Port),
		} {
			req, err := http.NewRequest(
				"GET",
				url,
				nil,
			)
			req.Header.Add("User-Agent", "curl/7.64.1")
			assert.NoError(t, err)
			req.Host = srv.RoutingTable.Ingresses.Items[0].Spec.Rules[0].Host

			res, err := http.DefaultClient.Do(req)
			assert.NoError(t, err)
			assert.Equal(t, 200, res.StatusCode)
		}
	})

	t.Run("test user_agent curl/7.64.2 should not be blocked", func(t *testing.T) {
		for _, url := range []string{
			fmt.Sprintf("https://%s:%d", reverseProxyConfig.Host, reverseProxyConfig.TlsPort),
			fmt.Sprintf("http://%s:%d", reverseProxyConfig.Host, reverseProxyConfig.Port),
		} {
			req, err := http.NewRequest(
				"GET",
				url,
				nil,
			)
			req.Header.Add("User-Agent", "curl/7.64.2")
			assert.NoError(t, err)
			req.Host = srv.RoutingTable.Ingresses.Items[0].Spec.Rules[0].Host

			res, err := http.DefaultClient.Do(req)
			assert.NoError(t, err)
			assert.Equal(t, 200, res.StatusCode)
		}
	})

	t.Run("test user_agent curl/7.66.3 should be blocked", func(t *testing.T) {
		for _, url := range []string{
			fmt.Sprintf("https://%s:%d", reverseProxyConfig.Host, reverseProxyConfig.TlsPort),
			fmt.Sprintf("http://%s:%d", reverseProxyConfig.Host, reverseProxyConfig.Port),
		} {
			req, err := http.NewRequest(
				"GET",
				url,
				nil,
			)
			req.Header.Add("User-Agent", "curl/7.66.3")
			assert.NoError(t, err)
			req.Host = srv.RoutingTable.Ingresses.Items[0].Spec.Rules[0].Host

			res, err := http.DefaultClient.Do(req)
			assert.NoError(t, err)
			assert.Equal(t, 403, res.StatusCode)
		}
	})
}

func TestRateLimitNotTriggeredOnWhitelistedPath(t *testing.T) {
	reverseProxyConfig := &Config{Host: "127.0.0.1", Port: freePort(), TlsPort: freePort()}
	mockServerConfig := &MockServerConfig{Host: "127.0.0.1.default.svc.cluster.local", Port: freePort()}
	numRequests := 10
	rateLimit := "1-S"
	ctx := context.Background()

	runMockServer(fmt.Sprintf("%s:%d", mockServerConfig.Host, mockServerConfig.Port), ctx)
	srv := New(reverseProxyConfig)

	ingressExactPathMock := mocks.IngressExactPathTypeMock()
	ingressExactPathMock.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number = int32(mockServerConfig.Port)
	ingressExactPathMock.Spec.Rules[0].HTTP.Paths[0].Path = "/.well-known"
	ingressExactPathMock.Annotations = map[string]string{
		// rate limited after more than 10 requests per second
		"guardgress/limit-period": rateLimit,
		// whitelist healthz path
		"guardgress/limit-path-whitelist": "/foo,/.well-known",
	}
	ingressLimiterPathExact := limithandler.GetIngressLimiter(ingressExactPathMock)

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
		_ = srv.Run(ctx)
	}()

	waitForServer(ctx, reverseProxyConfig.Port)

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	t.Run("Rate limit should not be triggered on whitelisted path", func(t *testing.T) {
		req, err := http.NewRequest(
			"GET",
			fmt.Sprintf("https://%s:%d/.well-known", reverseProxyConfig.Host, reverseProxyConfig.TlsPort),
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
	requestLimit := 10
	reverseProxyConfig := &Config{Host: "127.0.0.1", Port: freePort(), TlsPort: freePort()}
	mockServerConfig := &MockServerConfig{Host: "127.0.0.1.default.svc.cluster.local", Port: freePort()}
	ctx := context.Background()

	runMockServer(fmt.Sprintf("%s:%d", mockServerConfig.Host, mockServerConfig.Port), ctx)
	srv := New(reverseProxyConfig)

	ingressExactPathMock := mocks.IngressExactPathTypeMock()
	ingressExactPathMock.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number = int32(mockServerConfig.Port)
	ingressExactPathMock.Spec.Rules[0].HTTP.Paths[0].Path = "/bar"
	ingressExactPathMock.Annotations = map[string]string{
		// rate limited after more than 10 requests per second
		"guardgress/limit-period": fmt.Sprintf("%d-S", requestLimit),
	}
	ingressLimiterPathExact := limithandler.GetIngressLimiter(ingressExactPathMock)

	ingressPathPrefixMock := mocks.IngressPathTypePrefixMock()
	ingressPathPrefixMock.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number = int32(mockServerConfig.Port)
	ingressPathPrefixMock.Spec.Rules[0].HTTP.Paths[0].Path = "/foo"
	ingressPathPrefixMock.Annotations = map[string]string{}
	ingressLimiterPathPrefix := limithandler.GetIngressLimiter(ingressExactPathMock)

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
		_ = srv.Run(ctx)
	}()

	go func() {
		err := os.Setenv("HEALTH_METRICS_PORT", strconv.Itoa(freePort()))
		assert.NoError(t, err)
		err = healthmetrics.New().Run(ctx)
		assert.NoError(t, err)
	}()

	waitForServer(ctx, reverseProxyConfig.Port)

	// check if rate limit works
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	t.Run("test 10 simultaneously requests should not trigger rate limit (10S)", func(t *testing.T) {
		req, err := http.NewRequest(
			"GET",
			fmt.Sprintf("https://%s:%d/bar", reverseProxyConfig.Host, reverseProxyConfig.TlsPort),
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
	requestLimit := 60
	reverseProxyConfig := &Config{Host: "127.0.0.1", Port: freePort(), TlsPort: freePort()}
	mockServerConfig := &MockServerConfig{Host: "127.0.0.1.default.svc.cluster.local", Port: freePort()}
	ctx := context.Background()

	runMockServer(fmt.Sprintf("%s:%d", mockServerConfig.Host, mockServerConfig.Port), ctx)
	srv := New(reverseProxyConfig)

	ingressExactPathMock := mocks.IngressExactPathTypeMock()
	ingressExactPathMock.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number = int32(mockServerConfig.Port)
	ingressExactPathMock.Spec.Rules[0].HTTP.Paths[0].Path = "/bar"
	ingressExactPathMock.Annotations = map[string]string{
		// rate limited after more than 60 requests per hour
		"guardgress/limit-period": fmt.Sprintf("%d-M", requestLimit),
	}
	ingressLimiterPathExact := limithandler.GetIngressLimiter(ingressExactPathMock)

	ingressPathPrefixMock := mocks.IngressPathTypePrefixMock()
	ingressPathPrefixMock.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number = int32(mockServerConfig.Port)
	ingressPathPrefixMock.Spec.Rules[0].HTTP.Paths[0].Path = "/foo"
	ingressPathPrefixMock.Annotations = map[string]string{}
	ingressLimiterPathPrefix := limithandler.GetIngressLimiter(ingressExactPathMock)

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
		_ = srv.Run(ctx)
	}()

	waitForServer(ctx, reverseProxyConfig.Port)

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	t.Run("test 60 simultaneously requests should not trigger rate limit (60M)", func(t *testing.T) {
		req, err := http.NewRequest(
			"GET",
			fmt.Sprintf("https://%s:%d/bar", reverseProxyConfig.Host, reverseProxyConfig.TlsPort),
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
	requestLimit := 60
	reverseProxyConfig := &Config{Host: "127.0.0.1", Port: freePort(), TlsPort: freePort()}
	mockServerConfig := &MockServerConfig{Host: "127.0.0.1.default.svc.cluster.local", Port: freePort()}
	ctx := context.Background()

	runMockServer(fmt.Sprintf("%s:%d", mockServerConfig.Host, mockServerConfig.Port), ctx)
	srv := New(reverseProxyConfig)

	ingressExactPathMock := mocks.IngressExactPathTypeMock()
	ingressExactPathMock.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number = int32(mockServerConfig.Port)
	ingressExactPathMock.Spec.Rules[0].HTTP.Paths[0].Path = "/bar"
	ingressExactPathMock.Annotations = map[string]string{
		// rate limited after more than 60 requests per hour
		"guardgress/limit-period": fmt.Sprintf("%d-H", requestLimit),
	}
	ingressLimiterPathExact := limithandler.GetIngressLimiter(ingressExactPathMock)

	ingressPathPrefixMock := mocks.IngressPathTypePrefixMock()
	ingressPathPrefixMock.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number = int32(mockServerConfig.Port)
	ingressPathPrefixMock.Spec.Rules[0].HTTP.Paths[0].Path = "/foo"
	ingressPathPrefixMock.Annotations = map[string]string{}
	ingressLimiterPathPrefix := limithandler.GetIngressLimiter(ingressExactPathMock)

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
		_ = srv.Run(ctx)
	}()

	waitForServer(ctx, reverseProxyConfig.Port)

	// check if rate limit works
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	t.Run("test 60 simultaneously requests should not trigger rate limit (60H)", func(t *testing.T) {
		req, err := http.NewRequest(
			"GET",
			fmt.Sprintf("https://%s:%d/bar", reverseProxyConfig.Host, reverseProxyConfig.TlsPort),
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
	reverseProxyConfig := &Config{Host: "127.0.0.1", Port: freePort(), TlsPort: freePort()}
	mockServerConfig := &MockServerConfig{Host: "127.0.0.1.default.svc.cluster.local", Port: freePort()}
	ctx := context.Background()

	runMockServer(fmt.Sprintf("%s:%d", mockServerConfig.Host, mockServerConfig.Port), ctx)
	srv := New(reverseProxyConfig)

	ingressExactPathMock := mocks.IngressExactPathTypeMock()
	ingressExactPathMock.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number = int32(mockServerConfig.Port)
	ingressExactPathMock.Spec.Rules[0].HTTP.Paths[0].Path = "/bar"
	ingressExactPathMock.Annotations = map[string]string{
		"guardgress/user-agent-whitelist": "curl/7.64.*",
		"guardgress/user-agent-blacklist": "curl/7.64.*,curl/7.65.*",
	}
	ingressExactPathMock.Namespace = "test"
	ingressLimiterPathExact := limithandler.GetIngressLimiter(ingressExactPathMock)

	ingressPathPrefixMock := mocks.IngressPathTypePrefixMock()
	ingressPathPrefixMock.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number = int32(mockServerConfig.Port)
	ingressPathPrefixMock.Spec.Rules[0].HTTP.Paths[0].Path = "/foo"
	ingressPathPrefixMock.Annotations = map[string]string{}
	ingressExactPathMock.Namespace = "test"
	ingressLimiterPathPrefix := limithandler.GetIngressLimiter(ingressExactPathMock)

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
		_ = srv.Run(ctx)
	}()

	waitForServer(ctx, reverseProxyConfig.Port)

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	t.Run("test if user agent block works with multiple ingresses (curl/7.64.1 should work)", func(t *testing.T) {
		req, err := http.NewRequest(
			"GET",
			fmt.Sprintf("https://%s:%d/bar", reverseProxyConfig.Host, reverseProxyConfig.TlsPort),
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
			fmt.Sprintf("https://%s:%d/bar", reverseProxyConfig.Host, reverseProxyConfig.TlsPort),
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
			fmt.Sprintf("https://%s:%d/bar", reverseProxyConfig.Host, reverseProxyConfig.TlsPort),
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
			fmt.Sprintf("https://%s:%d/foo", reverseProxyConfig.Host, reverseProxyConfig.TlsPort),
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
			fmt.Sprintf("https://%s:%d/foo/bar", reverseProxyConfig.Host, reverseProxyConfig.TlsPort),
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
			fmt.Sprintf("https://%s:%d/foo/bar/../bar/bar", reverseProxyConfig.Host, reverseProxyConfig.TlsPort),
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

func TestProxyDirectorParams(t *testing.T) {
	reverseProxyConfig := &Config{Host: "127.0.0.1", Port: freePort(), TlsPort: freePort()}
	mockServerConfig := &MockServerConfig{Host: "127.0.0.1.default.svc.cluster.local", Port: freePort()}
	ctx := context.Background()

	runMockServer(fmt.Sprintf("%s:%d", mockServerConfig.Host, mockServerConfig.Port), ctx)
	srv := New(reverseProxyConfig)

	ingressExactPathMock := mocks.IngressExactPathTypeMock()
	ingressExactPathMock.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number = int32(mockServerConfig.Port)
	ingressExactPathMock.Spec.Rules[0].HTTP.Paths[0].Path = "/bar"
	ingressExactPathMock.Spec.Rules[0].Host = "www.guardgress.com"
	ingressLimiterPathExact := limithandler.GetIngressLimiter(ingressExactPathMock)

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
		_ = srv.Run(ctx)
	}()

	waitForServer(ctx, reverseProxyConfig.Port)

	t.Run("test proxy director params", func(t *testing.T) {
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		req, err := http.NewRequest(
			"GET",
			fmt.Sprintf("https://%s:%d/bar", reverseProxyConfig.Host, reverseProxyConfig.TlsPort),
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
	reverseProxyConfig := &Config{Host: "127.0.0.1", Port: freePort(), TlsPort: freePort()}
	mockServerConfig := &MockServerConfig{Host: "127.0.0.1.default.svc.cluster.local", Port: freePort()}
	ctx := context.Background()

	runMockServer(fmt.Sprintf("%s:%d", mockServerConfig.Host, mockServerConfig.Port), ctx)
	srv := New(reverseProxyConfig)

	ingressExactPathMock := mocks.IngressExactPathTypeMock()
	ingressExactPathMock.Annotations = map[string]string{
		"guardgress/force-ssl-redirect": "true",
	}
	ingressExactPathMock.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number = int32(mockServerConfig.Port)
	ingressLimiter := limithandler.GetIngressLimiter(ingressExactPathMock)

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
		_ = srv.Run(ctx)
	}()

	waitForServer(ctx, reverseProxyConfig.Port)

	// check if https redirect works
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	req, err := http.NewRequest(
		"GET",
		fmt.Sprintf("http://%s:%d", reverseProxyConfig.Host, reverseProxyConfig.Port),
		nil,
	)
	assert.NoError(t, err)
	req.Host = srv.RoutingTable.Ingresses.Items[0].Spec.Rules[0].Host

	_, err = http.DefaultClient.Do(req)
	// Error is expected. Just check if https redirect worked
	assert.True(t, strings.ContainsAny("https://127.0.0.1", err.Error()))
}

func TestHTTPSRequestIPWhitelistSourceRange(t *testing.T) {
	reverseProxyConfig := &Config{Host: "127.0.0.1", Port: freePort(), TlsPort: freePort()}
	mockServerConfig := &MockServerConfig{Host: "127.0.0.1.default.svc.cluster.local", Port: freePort()}
	ctx := context.Background()

	runMockServer(fmt.Sprintf("%s:%d", mockServerConfig.Host, mockServerConfig.Port), ctx)
	srv := New(reverseProxyConfig)

	ingressExactPathMock := mocks.IngressExactPathTypeMock()
	ingressExactPathMock.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number = int32(mockServerConfig.Port)
	ingressExactPathMock.Annotations = map[string]string{
		"guardgress/whitelist-ip-source-range": "192.168.0.0/24,192.169.0.0/24",
	}
	ingressLimiter := limithandler.GetIngressLimiter(ingressExactPathMock)

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
		_ = srv.Run(ctx)
	}()

	go func() {
		err := os.Setenv("HEALTH_METRICS_PORT", strconv.Itoa(freePort()))
		assert.NoError(t, err)
		err = healthmetrics.New().Run(ctx)
		assert.NoError(t, err)
	}()

	waitForServer(ctx, reverseProxyConfig.Port)

	t.Run("test if ip whitelist source range works", func(t *testing.T) {
		// check if reverse proxy works for https request
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		req, err := http.NewRequest(
			"GET",
			fmt.Sprintf("https://%s:%d", reverseProxyConfig.Host, reverseProxyConfig.TlsPort),
			nil,
		)
		assert.NoError(t, err)
		req.Host = srv.RoutingTable.Ingresses.Items[0].Spec.Rules[0].Host

		res, err := http.DefaultClient.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, 401, res.StatusCode)
	})
}

func TestHTTPSRequestIPWhitelistSourceRangeError(t *testing.T) {
	reverseProxyConfig := &Config{Host: "127.0.0.1", Port: freePort(), TlsPort: freePort()}
	mockServerConfig := &MockServerConfig{Host: "127.0.0.1.default.svc.cluster.local", Port: freePort()}
	ctx := context.Background()

	runMockServer(fmt.Sprintf("%s:%d", mockServerConfig.Host, mockServerConfig.Port), ctx)
	srv := New(reverseProxyConfig)

	ingressExactPathMock := mocks.IngressExactPathTypeMock()
	ingressExactPathMock.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number = int32(mockServerConfig.Port)
	ingressExactPathMock.Annotations = map[string]string{
		"guardgress/whitelist-ip-source-range": "192.168.ABC.ABC/24",
	}
	ingressLimiter := limithandler.GetIngressLimiter(ingressExactPathMock)

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
		_ = srv.Run(ctx)
	}()

	go func() {
		err := os.Setenv("HEALTH_METRICS_PORT", strconv.Itoa(freePort()))
		assert.NoError(t, err)
		err = healthmetrics.New().Run(ctx)
		assert.NoError(t, err)
	}()

	waitForServer(ctx, reverseProxyConfig.Port)

	t.Run("test if ip whitelist source range throws error with faulty annotation", func(t *testing.T) {
		// check if reverse proxy works for https request
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		req, err := http.NewRequest(
			"GET",
			fmt.Sprintf("https://%s:%d", reverseProxyConfig.Host, reverseProxyConfig.TlsPort),
			nil,
		)
		assert.NoError(t, err)
		req.Host = srv.RoutingTable.Ingresses.Items[0].Spec.Rules[0].Host

		res, err := http.DefaultClient.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusInternalServerError, res.StatusCode)
	})
}

// This is the last test which tracks if the metrics are working
func TestCustomPrometheusMetrics(t *testing.T) {
	healthMetricsPort := freePort()
	ctx := context.Background()

	go func(port int, ctx context.Context) {
		err := os.Setenv("HEALTH_METRICS_PORT", strconv.Itoa(healthMetricsPort))
		assert.NoError(t, err)
		err = healthmetrics.New().Run(ctx)
		assert.NoError(t, err)
	}(healthMetricsPort, ctx)

	waitForServer(ctx, healthMetricsPort)

	// check if metrics are working
	res, err := http.Get(fmt.Sprintf("http://0.0.0.0:%d/metrics", healthMetricsPort))
	assert.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)
	bs, err := io.ReadAll(res.Body)
	t.Log(string(bs))
	assert.NoError(t, err)

	metricsWhichShouldBePresent := []string{
		"http_https_request_count",
		"http_https_request_status_code_count",
		"http_https_request_duration_seconds",
		"concurrent_requests",
		"rate_limit_blocks",
		"user_agent_blocks",
		"ip_forbidden_blocks",
	}

	for _, metric := range metricsWhichShouldBePresent {
		t.Run("test if metric "+metric+" is present", func(t *testing.T) {
			assert.True(t, strings.ContainsAny(string(bs), metric))
		})
	}
}

func runMockServer(addr string, ctx context.Context) {
	fmt.Print(addr)
	mockSrv := &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// set for TestTlsFingerprintingAddHeader Test
			for _, v := range []string{"X-Ja3-Fingerprint", "X-Ja4-Fingerprint"} {
				if ok := r.Header.Get(v); ok != "" {
					w.Header().Set(v, r.Header.Get(v))
				}
			}

			// set for TestProxyDirectorParams Test
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
		if err != nil {
			log.Fatalf("Mock server error: %s", err)
		}
	}()
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
