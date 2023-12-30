package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"time"

	"github.com/caarlos0/env"
	"github.com/gin-gonic/gin"
	"github.com/h3adex/fp"
	"github.com/h3adex/guardgress/pkg/annotations"
	"github.com/h3adex/guardgress/pkg/models"
	"github.com/h3adex/guardgress/pkg/router"
	"github.com/h3adex/guardgress/pkg/watcher"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

const (
	InternalErrorResponse  = "Internal Server Error"
	ForbiddenErrorResponse = "Forbidden"
)

const (
	NoErrorIdentifier = iota
	InternalErrorIdentifier
	UserAgentForbiddenIdentifier
	TlsFingerprintForbiddenIdentifier
	IPForbiddenIdentifier
	RateLimitedErrorIdentifier
)

var (
	reqCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "http_https_request_count",
		Help: "Total number of HTTP and HTTPS requests",
	}, []string{"protocol"})

	reqStatusCodeCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "http_https_request_status_code_count",
		Help: "HTTP and HTTPS request count by status code",
	}, []string{"protocol", "status_code"})

	reqDurationHistogram = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "http_https_request_duration_seconds",
		Help:    "Duration of HTTP and HTTPS requests",
		Buckets: prometheus.DefBuckets,
	}, []string{"protocol"})

	concurrentReqGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "concurrent_requests",
		Help: "Current number of concurrent requests",
	})

	rateLimitBlocks = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "rate_limit_blocks",
		Help: "Number of requests blocked due to rate limiting",
	}, []string{"protocol", "endpoint"})

	ipForbiddenBlocks = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ip_forbidden_blocks",
		Help: "Number of requests blocked due to ip blocks",
	}, []string{"protocol"})

	tlsFingerprintBlocks = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "tls_fingerprint_blocks",
		Help: "Number of requests blocked due to TLS fingerprinting",
	}, []string{"protocol", "fingerprint"})

	userAgentBlocks = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "user_agent_blocks",
		Help: "Number of requests blocked due to user agent",
	}, []string{"protocol", "user_agent"})
)

type Config struct {
	Host    string `env:"HOST" envDefault:"0.0.0.0"`
	Port    int    `env:"PORT" envDefault:"80"`
	TlsPort int    `env:"TLS_PORT" envDefault:"443"`
}

type Server struct {
	Config       *Config
	RoutingTable *router.RoutingTable
}

// New creates a new Server instance.
func New(config *Config) *Server {
	routingTable := &router.RoutingTable{}
	if err := env.Parse(routingTable); err != nil {
		log.Fatalf("Error parsing routing table: %v", err)
	}

	return &Server{
		Config:       config,
		RoutingTable: routingTable,
	}
}

// UpdateRoutingTable updates the server's routing table based on the provided payload.
func (s Server) UpdateRoutingTable(payload watcher.Payload) {
	s.RoutingTable.Update(payload)
}

// Run starts the HTTP and HTTPS servers.
func (s Server) Run(ctx context.Context) error {
	eg, egCtx := errgroup.WithContext(ctx)

	eg.Go(func() error {
		return s.startHTTPServer(egCtx)
	})

	eg.Go(func() error {
		return s.startHTTPSServer(egCtx)
	})

	return eg.Wait()
}

func (s Server) startHTTPServer(ctx context.Context) error {
	log.Infof("Starting HTTP Server on port %d", s.Config.Port)
	handler := s.setupRouter("http")

	server := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", s.Config.Host, s.Config.Port),
		Handler: handler,
	}

	go s.shutdownServerOnContextCancel(ctx, server, "HTTP")

	return server.ListenAndServe()
}

func (s Server) startHTTPSServer(ctx context.Context) error {
	log.Infof("Starting HTTPS Server on port %d", s.Config.TlsPort)
	handler := s.setupRouter("https")

	err := fp.Server(
		ctx,
		handler.Handler(),
		fp.Option{
			Addr: fmt.Sprintf("%s:%d", s.Config.Host, s.Config.TlsPort),
			GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				return s.RoutingTable.GetTlsCertificate(clientHello.ServerName)
			},
		},
	)

	if err != nil {
		log.Errorf("Error on HTTPS server: %v", err)
		return err
	}

	return nil
}

func (s Server) setupRouter(protocol string) *gin.Engine {
	handler := gin.Default()
	handler.Any("/*path", func(c *gin.Context) {
		startTime := time.Now()
		concurrentReqGauge.Inc()

		errorIdentifier := s.proxyRequest(c, protocol == "https")

		duration := time.Since(startTime)
		reqDurationHistogram.WithLabelValues(protocol).Observe(duration.Seconds())
		reqCounter.WithLabelValues(protocol).Inc()
		statusCode := strconv.Itoa(c.Writer.Status())
		reqStatusCodeCounter.WithLabelValues(protocol, statusCode).Inc()

		switch errorIdentifier {
		case RateLimitedErrorIdentifier:
			rateLimitBlocks.WithLabelValues(protocol, c.Request.RequestURI).Inc()
		case UserAgentForbiddenIdentifier:
			userAgentBlocks.WithLabelValues(protocol, c.Request.UserAgent()).Inc()
		case TlsFingerprintForbiddenIdentifier:
			fingerprint, ok := c.Value("fingerprint").(string)
			if ok {
				tlsFingerprintBlocks.WithLabelValues(protocol, fingerprint).Inc()
			}
		case IPForbiddenIdentifier:
			ipForbiddenBlocks.WithLabelValues(protocol).Inc()
		default:
			// NoErrorIdentifier, InternalErrorIdentifier:
			return
		}

		concurrentReqGauge.Dec()
	})

	return handler
}

// proxyRequest handles the forwarding of incoming requests to the designated backend service.
// This function also manages various security and redirection protocols based on request attributes and annotations.
func (s Server) proxyRequest(ctx *gin.Context, isHTTPS bool) int {
	host := ctx.Request.Host
	requestURI := ctx.Request.RequestURI
	clientIP := ctx.ClientIP()

	// Retrieve the backend service URL, annotations, and check for any routing errors.
	// This includes validating if the request can be serviced by a backend and if it adheres to rate limits.
	svcURL, parsedAnnotations, routingError := s.RoutingTable.GetBackend(host, requestURI, clientIP)
	log.Debugf("Parsed annotations: %+v", parsedAnnotations)

	// Handle any routing errors, sending appropriate HTTP responses and logging the issues.
	if routingError.Error != nil {
		log.Errorf("Routing error: %v", routingError.Error)
		ctx.Writer.WriteHeader(routingError.StatusCode)
		_, _ = ctx.Writer.Write([]byte(routingError.Error.Error()))
		if routingError.StatusCode == http.StatusTooManyRequests {
			return RateLimitedErrorIdentifier
		}

		return InternalErrorIdentifier
	}

	// Redirect HTTP requests to HTTPS if the 'Force SSL' annotation is present and true.
	forceSSL, forceSSLExists := parsedAnnotations[annotations.ForceSSLRedirect]
	if !isHTTPS && forceSSLExists && forceSSL == "true" {
		httpsURL := fmt.Sprintf("https://%s%s", host, requestURI)
		log.Debugf("Redirecting HTTP request to HTTPS: %s", httpsURL)
		http.Redirect(ctx.Writer, ctx.Request, httpsURL, http.StatusMovedPermanently)
		return NoErrorIdentifier
	}

	// Evaluate if the client IP is authorized to access the service based on annotations.
	ipIsAllowed, err := annotations.IsIpAllowed(parsedAnnotations, clientIP)
	if err != nil {
		log.Errorf("Error checking if IP is allowed: %v", err)
		ctx.Writer.WriteHeader(http.StatusInternalServerError)
		_, _ = ctx.Writer.Write([]byte(InternalErrorResponse))
		return InternalErrorIdentifier
	}

	// Deny access if the client IP is not authorized.
	if !ipIsAllowed {
		log.Debugf("IP not allowed: %s", clientIP)
		ctx.Writer.WriteHeader(http.StatusUnauthorized)
		_, _ = ctx.Writer.Write([]byte(ForbiddenErrorResponse))
		return IPForbiddenIdentifier
	}
	log.Debugf("IP is allowed: %s", clientIP)

	// Validate TLS fingerprint if the connection is HTTPS and the corresponding annotation exists.
	if isHTTPS && annotations.TlsFingerprintAnnotationExists(parsedAnnotations) {
		parsedClientHello, err := s.parseClientHello(ctx, parsedAnnotations)
		if err != nil {
			log.Errorf("Error processing TLS request: %v", err)
			ctx.Writer.WriteHeader(http.StatusInternalServerError)
			_, _ = ctx.Writer.Write([]byte(InternalErrorResponse))
			return InternalErrorIdentifier
		}
		// Block the request if the TLS fingerprint is not allowed.
		if ok, blockedFp := annotations.IsTLSFingerprintAllowed(parsedAnnotations, parsedClientHello); !ok {
			ctx.Set("fingerprint", blockedFp)
			ctx.Writer.WriteHeader(http.StatusForbidden)
			_, _ = ctx.Writer.Write([]byte(ForbiddenErrorResponse))
			return TlsFingerprintForbiddenIdentifier
		}
	}

	// Check if the user-agent is permitted to access the service.
	if !annotations.IsUserAgentAllowed(parsedAnnotations, ctx.Request.UserAgent()) {
		log.Warnf("Request not allowed: %s", requestURI)
		ctx.Writer.WriteHeader(http.StatusForbidden)
		_, _ = ctx.Writer.Write([]byte(ForbiddenErrorResponse))
		return UserAgentForbiddenIdentifier
	}

	// Finally, forward the validated request to the backend service.
	s.proxyToBackend(ctx, svcURL, host)

	return NoErrorIdentifier
}

func (s Server) parseClientHello(ctx *gin.Context, parsedAnnotations map[string]string) (models.ParsedClientHello, error) {
	parsedClientHello, err := models.ParseClientHello(ctx)
	if err != nil {
		return models.ParsedClientHello{}, fmt.Errorf("unable to parse client hello: %w", err)
	}
	log.Debugf("ParsedClientHello: %+v", parsedClientHello)

	if annotations.IsTLSFingerprintHeaderRequested(parsedAnnotations) {
		addTLSFingerprintHeaders(ctx, parsedClientHello)
	}

	return parsedClientHello, nil
}

func (s Server) proxyToBackend(ctx *gin.Context, svcURL *url.URL, host string) {
	log.Debugf("Proxying request to backend service: %s", svcURL)
	proxy := httputil.NewSingleHostReverseProxy(svcURL)
	proxy.Director = func(req *http.Request) {
		req.Header = ctx.Request.Header
		req.Host = host
		req.URL.Scheme = svcURL.Scheme
		req.URL.Host = svcURL.Host
		req.URL.Path = svcURL.Path
	}
	proxy.ServeHTTP(ctx.Writer, ctx.Request)
}

// shutdownServerOnContextCancel shuts down the server when the context is canceled.
func (s Server) shutdownServerOnContextCancel(ctx context.Context, server *http.Server, serverType string) {
	<-ctx.Done()
	if err := server.Shutdown(context.Background()); err != nil {
		log.Errorf("Error shutting down %s server: %v", serverType, err)
	}
}

func addTLSFingerprintHeaders(ctx *gin.Context, clientHello models.ParsedClientHello) {
	ctx.Request.Header.Add("X-Ja3-Fingerprint", clientHello.Ja3)
	ctx.Request.Header.Add("X-Ja3-Fingerprint-Hash", clientHello.Ja3H)
	ctx.Request.Header.Add("X-Ja3n-Fingerprint", clientHello.Ja3n)
	ctx.Request.Header.Add("X-Ja4-Fingerprint", clientHello.Ja4)
	ctx.Request.Header.Add("X-Ja4h-Fingerprint", clientHello.Ja4h)
}
