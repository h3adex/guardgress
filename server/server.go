package server

import (
	"bufio"
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"github.com/h3adex/phalanx/crypto/tls"
	"github.com/h3adex/phalanx/net/http"
	"github.com/h3adex/phalanx/net/http/httputil"
	"github.com/h3adex/phalanx/watcher"
	"io"
	stdlog "log"
	"strings"
	"sync/atomic"

	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"
)

// A Server serves HTTP pages.
type Server struct {
	cfg          *config
	routingTable atomic.Value

	ready *Event
}

// New creates a new Server.
func New(options ...Option) *Server {
	cfg := defaultConfig()
	for _, o := range options {
		o(cfg)
	}
	s := &Server{
		cfg:   cfg,
		ready: NewEvent(),
	}
	s.routingTable.Store(NewRoutingTable(nil))
	return s
}

// Run runs the server.
func (s *Server) Run(ctx context.Context) error {
	// don't start listening until the first payload
	s.ready.Wait(ctx)

	pr, pw := io.Pipe()
	go readHTTPLogs(pr)

	var eg errgroup.Group
	eg.Go(func() error {
		srv := http.Server{
			Addr:     fmt.Sprintf("%s:%d", s.cfg.host, s.cfg.tlsPort),
			Handler:  s,
			ErrorLog: stdlog.New(pw, "", 0),
		}
		srv.TLSConfig = &tls.Config{
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				return s.routingTable.Load().(*RoutingTable).GetCertificate(hello.ServerName)
			},
		}
		log.Info().Str("addr", srv.Addr).Msg("starting secure HTTP server")
		err := srv.ListenAndServeTLS("", "")
		if err != nil {
			return fmt.Errorf("error serving tls: %w", err)
		}
		return nil
	})
	eg.Go(func() error {
		srv := http.Server{
			Addr:     fmt.Sprintf("%s:%d", s.cfg.host, s.cfg.port),
			Handler:  s,
			ErrorLog: stdlog.New(pw, "", 0),
		}
		log.Info().Str("addr", srv.Addr).Msg("starting insecure HTTP server")
		err := srv.ListenAndServe()
		if err != nil {
			return fmt.Errorf("error serving non-tls: %w", err)
		}
		return nil
	})
	return eg.Wait()
}

func JA3Digest(ja3 string) string {
	h := md5.New()
	h.Write([]byte(ja3))
	return hex.EncodeToString(h.Sum(nil))
}

// ServeHTTP serves an HTTP request.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	backendURL, err := s.routingTable.Load().(*RoutingTable).GetBackend(r.Host, r.URL.Path)
	if err != nil {
		http.Error(w, "upstream server not found", http.StatusNotFound)
		return
	}
	r.Header.Set("x-ja3", JA3Digest(r.JA3))

	log.Info().Str("host", r.Host).Str("path", r.URL.Path).Str("backend", backendURL.String()).Msg("proxying request")
	p := httputil.NewSingleHostReverseProxy(backendURL)
	if backendURL.Scheme == "https" {
		/*p.Transport = &http2.Transport{
			AllowHTTP: true,
		}*/
	}
	p.ErrorLog = stdlog.New(log.Logger, "", 0)
	p.ServeHTTP(w, r)
}

// Update updates the server with new ingress rules.
func (s *Server) Update(payload *watcher.Payload) {
	s.routingTable.Store(NewRoutingTable(payload))
	s.ready.Set()
}

func readHTTPLogs(r io.Reader) {
	br := bufio.NewReader(r)
	for {
		ln, err := br.ReadString('\n')
		if err != nil {
			return
		}
		log.Info().Msg(strings.TrimSpace(ln))
	}
}
