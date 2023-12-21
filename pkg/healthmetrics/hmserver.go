package healthmetrics

import (
	"context"
	"fmt"
	"github.com/caarlos0/env"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"net/http"
)

type Server struct {
	Host string `env:"HEALTH_METRICS_HOST" envDefault:"0.0.0.0"`
	Port int    `env:"HEALTH_METRICS_PORT" envDefault:"10254"`
}

func New() *Server {
	server := &Server{}
	if err := env.Parse(server); err != nil {
		log.Panic(err)
	}

	return server
}

func (s Server) Run(ctx context.Context) error {
	log.Infof("Starting Healthmetrics Server on Port %d", s.Port)
	handler := gin.Default()

	// healthz route
	handler.GET("/healthz", func(c *gin.Context) {
		_, _ = c.Writer.Write([]byte("OK!"))
		c.Writer.WriteHeader(http.StatusOK)
	})

	// prometheus metrics route
	promHandler := promhttp.Handler()
	handler.GET("/metrics", func(c *gin.Context) {
		promHandler.ServeHTTP(c.Writer, c.Request)
	})

	server := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", s.Host, s.Port),
		Handler: handler,
	}

	go func(ctx context.Context) {
		<-ctx.Done()
		if err := server.Shutdown(context.Background()); err != nil {
			log.Errorf("Error shutting down %s", err)
		}
	}(ctx)

	return server.ListenAndServe()
}
