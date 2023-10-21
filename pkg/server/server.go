package server

import (
	"context"
	"fmt"
	"github.com/h3adex/phalanx/internal/crypto/tls"
	"github.com/h3adex/phalanx/internal/net/http"
	"github.com/h3adex/phalanx/internal/net/http/httputil"
	"github.com/h3adex/phalanx/pkg/annotations"
	"github.com/h3adex/phalanx/pkg/ja3"
	"github.com/h3adex/phalanx/pkg/router"
	"github.com/h3adex/phalanx/pkg/watcher"
	"log"
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
	return s
}

func (s Server) Run(ctx context.Context) {
	wg := sync.WaitGroup{}

	wg.Add(1)
	go func() {
		srv := http.Server{
			Addr:    fmt.Sprintf("%s:%d", s.Config.Host, s.Config.Port),
			Handler: s,
		}
		log.Println("Starting HTTP-Server on ", srv.Addr)
		err := srv.ListenAndServe()
		if err != nil {
			panic(err)
		}
	}()

	wg.Add(1)
	go func() {
		srv := http.Server{
			Addr:    fmt.Sprintf("%s:%d", s.Config.Host, s.Config.TlsPort),
			Handler: s,
		}
		srv.TLSConfig = &tls.Config{
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				return s.RoutingTable.GetTlsCertificate(hello.ServerName)
			},
		}
		log.Println("Starting HTTPS-Server on ", srv.Addr)
		err := srv.ListenAndServeTLS("", "")
		if err != nil {
			panic(err)
		}
	}()

	wg.Wait()
}

func (s Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	svcUrl, parsedAnnotations, err := s.RoutingTable.GetBackend(request.Host, request.RequestURI)
	if err != nil {
		writer.WriteHeader(404)
		_, _ = writer.Write([]byte("404 - Not Found"))
		return
	}

	ja3Digest := ja3.Digest(request.JA3)
	if annotations.IsJa3Blacklisted(parsedAnnotations, ja3Digest) {
		writer.WriteHeader(403)
		_, _ = writer.Write([]byte("403 - Forbidden"))
		return
	}

	if annotations.AddJa3Header(parsedAnnotations) {
		request.Header.Add("X-Ja3-Fingerprint", ja3Digest)
	}

	p := httputil.NewSingleHostReverseProxy(svcUrl)
	p.ServeHTTP(writer, request)
}

func (s Server) UpdateRoutingTable(payload watcher.Payload) {
	s.RoutingTable.Update(payload)
}
