package healthmetrics

import (
	"context"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestHealthzRoute(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	fPort := freePort()
	_ = os.Setenv("HEALTH_METRICS_PORT", fmt.Sprintf("%d", fPort))
	defer cancel()

	var wg sync.WaitGroup
	go func(ctx context.Context) {
		wg.Add(1)
		_ = New().Run(ctx)
	}(ctx)

	waitForServer(ctx, fPort)

	t.Run("test if healthz route is providing status code", func(t *testing.T) {
		resp, err := http.Get(fmt.Sprintf("http://0.0.0.0:%d/healthz", fPort))
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		wg.Done()
	})

	wg.Wait()
}

func TestMetricsRoute(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fPort := freePort()
	_ = os.Setenv("HEALTH_METRICS_PORT", fmt.Sprintf("%d", fPort))

	var wg sync.WaitGroup
	go func(ctx context.Context) {
		wg.Add(1)
		_ = New().Run(ctx)
	}(ctx)

	waitForServer(ctx, 10254)

	t.Run("test if metrics route is running like expected", func(t *testing.T) {
		resp, err := http.Get(fmt.Sprintf("http://0.0.0.0:%d/metrics", fPort))
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)

		// check if basic metric is present
		assert.True(t, strings.ContainsAny(string(body), "concurrent_requests"))
		wg.Done()
	})

	wg.Wait()
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
