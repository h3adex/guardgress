package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/caarlos0/env"
	"github.com/gin-gonic/gin"
	"github.com/gospider007/net/http2"
	"github.com/h3adex/fp"
	"github.com/h3adex/guardgress/pkg/algorithms"
	"github.com/h3adex/guardgress/pkg/annotations"
	"github.com/h3adex/guardgress/pkg/models"
	"github.com/h3adex/guardgress/pkg/router"
	"github.com/h3adex/guardgress/pkg/watcher"
	log "github.com/sirupsen/logrus"
	"net/http"
	"net/http/httputil"
	"sync"
)

const (
	InternalErrorResponse  = "Internal Server Error"
	ForbiddenErrorResponse = "Forbidden"
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

func New(config *Config) *Server {
	routingTable := &router.RoutingTable{}
	if err := env.Parse(routingTable); err != nil {
		log.Fatalln(err)
	}

	s := &Server{
		Config:       config,
		RoutingTable: routingTable,
	}

	return s
}

func (s Server) Run(ctx context.Context) {
	wg := sync.WaitGroup{}

	wg.Add(1)
	go func() {
		log.Info("Starting HTTP-Server on ", s.Config.Port)
		handle := gin.Default()
		handle.Any("/*path", s.ServeHTTP)
		err := http.ListenAndServe(fmt.Sprintf("%s:%d", s.Config.Host, s.Config.Port), handle)
		if err != nil {
			panic(err)
		}
	}()

	wg.Add(1)
	go func() {
		log.Info("Starting HTTPS-Server on ", s.Config.TlsPort)
		handle := gin.Default()
		handle.Any("/*path", s.ServeHttps)
		err := fp.Server(
			nil,
			handle.Handler(),
			fp.Option{
				Addr: fmt.Sprintf("%s:%d", s.Config.Host, s.Config.TlsPort),
				GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
					return s.RoutingTable.GetTlsCertificate(clientHello.ServerName)
				},
			},
		)
		if err != nil {
			panic(err)
		}
	}()
	wg.Wait()
}

func (s Server) ServeHttps(ctx *gin.Context) {
	// check if this request is used to determine the health of the service
	if ctx.Request.RequestURI == "/healthz" {
		s.healthz(ctx)
		return
	}

	req, err := httputil.DumpRequest(ctx.Request, true)
	log.Debug("request coming from ip: ", ctx.ClientIP())
	log.Debug("request dump: ", string(req))

	svcUrl, parsedAnnotations, routingError := s.RoutingTable.GetBackend(
		ctx.Request.Host,
		ctx.Request.RequestURI,
		ctx.ClientIP(),
	)
	log.Debug("parsed annotations: ", parsedAnnotations)

	if routingError.Error != nil {
		ctx.Writer.WriteHeader(routingError.StatusCode)
		_, _ = ctx.Writer.Write([]byte(routingError.Error.Error()))
		return
	}

	parsedClientHello, err := models.ParseClientHello(ctx)
	log.Debug("parsed ja3: ", parsedClientHello.Ja3)
	log.Debug("parsed ja4: ", parsedClientHello.Ja4)

	if err != nil {
		log.Error("unable to parse client hello: ", err.Error())
		ctx.Writer.WriteHeader(503)
		_, _ = ctx.Writer.Write([]byte(InternalErrorResponse))
		return
	}

	if annotations.IsTlsFingerprintBlacklisted(parsedAnnotations, parsedClientHello) {
		ctx.Writer.WriteHeader(403)
		_, _ = ctx.Writer.Write([]byte(ForbiddenErrorResponse))
		return
	}

	if annotations.IsUserAgentBlacklisted(parsedAnnotations, parsedClientHello.UserAgent) {
		ctx.Writer.WriteHeader(403)
		_, _ = ctx.Writer.Write([]byte(ForbiddenErrorResponse))
		return
	}

	if annotations.AddJa3Header(parsedAnnotations) {
		ctx.Request.Header.Add("X-Ja3-Fingerprint", parsedClientHello.Ja3)
		ctx.Request.Header.Add("X-Ja3-Fingerprint-Hash", algorithms.Ja3Digest(parsedClientHello.Ja3))
		ctx.Request.Header.Add("X-Ja3n-Fingerprint", parsedClientHello.Ja3n)
	}

	if annotations.AddJa4Header(parsedAnnotations) {
		ctx.Request.Header.Add("X-Ja4-Fingerprint", parsedClientHello.Ja4)
		ctx.Request.Header.Add("X-Ja4h-Fingerprint", parsedClientHello.Ja4h)
	}

	log.Debug("proxying https request to: ", svcUrl)
	proxy := httputil.NewSingleHostReverseProxy(svcUrl)

	if svcUrl.Scheme == "https" {
		proxy.Transport = &http2.Transport{
			AllowHTTP: true,
		}
	}

	ctx.Request.Header.Add("X-Forwarded-For", ctx.ClientIP())
	proxy.Director = func(req *http.Request) {
		req.Header = ctx.Request.Header
		req.Host = ctx.Request.Host
		req.URL.Scheme = svcUrl.Scheme
		req.URL.Host = svcUrl.Host
		req.URL.Path = svcUrl.Path
	}

	proxy.ServeHTTP(ctx.Writer, ctx.Request)
}

func (s Server) ServeHTTP(ctx *gin.Context) {
	if ctx.Request.RequestURI == "/healthz" {
		s.healthz(ctx)
		return
	}

	log.Debug("request coming from ip: ", ctx.ClientIP())

	svcUrl, _, routingError := s.RoutingTable.GetBackend(
		ctx.Request.Host,
		ctx.Request.RequestURI,
		ctx.ClientIP(),
	)

	if routingError.Error != nil {
		ctx.Writer.WriteHeader(routingError.StatusCode)
		_, _ = ctx.Writer.Write([]byte(routingError.Error.Error()))
		return
	}

	log.Debug("proxying http request to: ", svcUrl)
	proxy := httputil.NewSingleHostReverseProxy(svcUrl)

	if svcUrl.Scheme == "https" {
		proxy.Transport = &http2.Transport{
			AllowHTTP: true,
		}
	}

	ctx.Request.Header.Add("X-Forwarded-For", ctx.ClientIP())
	proxy.Director = func(req *http.Request) {
		req.Header = ctx.Request.Header
		req.Host = ctx.Request.Host
		req.URL.Scheme = svcUrl.Scheme
		req.URL.Host = svcUrl.Host
		req.URL.Path = svcUrl.Path
	}

	proxy.ServeHTTP(ctx.Writer, ctx.Request)
}

func (s Server) healthz(ctx *gin.Context) {
	ctx.Writer.WriteHeader(200)
	_, err := ctx.Writer.Write([]byte("ok"))
	if err != nil {
		log.Error("unable to write healthz response: ", err.Error())
	}
}

func (s Server) UpdateRoutingTable(payload watcher.Payload) {
	s.RoutingTable.Update(payload)
}
