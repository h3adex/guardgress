package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/gospider007/ja3"
	"github.com/gospider007/requests"
	"github.com/h3adex/fp"
	"github.com/h3adex/guardgress/pkg/algorithms"
	"github.com/h3adex/guardgress/pkg/annotations"
	"github.com/h3adex/guardgress/pkg/models"
	"github.com/h3adex/guardgress/pkg/router"
	"github.com/h3adex/guardgress/pkg/watcher"
	"log"
	"net/http"
	"net/http/httputil"
	"sync"
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
	s := &Server{
		Config:       config,
		RoutingTable: &router.RoutingTable{},
	}

	if s.Config.TlsPort > 443 {
		s.RoutingTable.DevMode = true
	}

	return s
}

func (s Server) Run(ctx context.Context) {
	wg := sync.WaitGroup{}

	wg.Add(1)
	go func() {
		log.Println("Starting HTTP-Server on ", s.Config.Port)
		srv := http.Server{
			Addr:    fmt.Sprintf("%s:%d", s.Config.Host, s.Config.Port),
			Handler: s,
		}
		err := srv.ListenAndServe()
		if err != nil {
			panic(err)
		}
	}()

	wg.Add(1)
	go func() {
		log.Println("Starting HTTPS-Server on ", s.Config.TlsPort)
		handle := gin.Default()
		handle.NoRoute(s.serveHttps)
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
			log.Fatalln(err)
		}
	}()
	wg.Wait()
}

func (s Server) parseClientHello(ctx *gin.Context) (models.ClientHelloParsed, error) {
	fpData, ok := ja3.GetFpContextData(ctx.Request.Context())
	connectionState := fpData.ConnectionState()

	result := models.ClientHelloParsed{
		NegotiatedProtocol: connectionState.NegotiatedProtocol,
		TlsVersion:         connectionState.Version,
		UserAgent:          ctx.Request.UserAgent(),
		OrderHeaders:       fpData.OrderHeaders(),
		Cookies:            requests.Cookies(ctx.Request.Cookies()).String(),
		Tls:                ja3.TlsData{},
		Ja3:                "",
		Ja3n:               "",
		Ja4:                "",
		Ja4h:               "",
	}

	tlsData, err := fpData.TlsData()
	if err == nil {
		result.Tls = tlsData
		result.Ja3, result.Ja3n = tlsData.Fp()
		result.Ja4 = tlsData.Ja4()
		result.Ja4h = fpData.Ja4H(ctx.Request)
	}

	if ok {
		return result, nil
	}

	return result, fmt.Errorf("unable to fingerprint tls handshake")
}

func (s Server) serveHttps(ctx *gin.Context) {
	ctx.Header("Access-Control-Allow-Origin", "*")
	svcUrl, parsedAnnotations, err := s.RoutingTable.GetBackend(
		ctx.Request.Host,
		ctx.Request.RequestURI,
	)

	if err != nil {
		ctx.Writer.WriteHeader(404)
		_, _ = ctx.Writer.Write([]byte("Not Found"))
		return
	}

	parsedClientHello, err := s.parseClientHello(ctx)

	if err != nil {
		log.Println(err.Error())
		ctx.Writer.WriteHeader(502)
		_, _ = ctx.Writer.Write([]byte("Error"))
		return
	}

	if annotations.IsTlsFingerprintBlacklisted(parsedAnnotations, parsedClientHello) {
		ctx.Writer.WriteHeader(403)
		_, _ = ctx.Writer.Write([]byte("Forbidden"))
		return
	}

	if annotations.IsUserAgentBlacklisted(parsedAnnotations, parsedClientHello.UserAgent) {
		ctx.Writer.WriteHeader(403)
		_, _ = ctx.Writer.Write([]byte("Forbidden"))
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

	proxy := httputil.NewSingleHostReverseProxy(svcUrl)
	proxy.Director = func(req *http.Request) {
		req.Header = ctx.Request.Header
		req.Host = svcUrl.Host
		req.URL.Scheme = svcUrl.Scheme
		req.URL.Host = svcUrl.Host
		req.URL.Path = ctx.Param("proxyPath")
	}

	proxy.ServeHTTP(ctx.Writer, ctx.Request)
}

func (s Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	svcUrl, _, err := s.RoutingTable.GetBackend(request.Host, request.RequestURI)
	if err != nil {
		writer.WriteHeader(404)
		_, _ = writer.Write([]byte("404 - Not Found"))
		return
	}
	p := httputil.NewSingleHostReverseProxy(svcUrl)
	p.ServeHTTP(writer, request)
}

func (s Server) UpdateRoutingTable(payload watcher.Payload) {
	s.RoutingTable.Update(payload)
}
