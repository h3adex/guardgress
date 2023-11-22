package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/h3adex/guardgress/pkg/mocks"
	"github.com/h3adex/guardgress/pkg/router"
	"github.com/stretchr/testify/assert"
	"io"
	"log"
	"net"
	"net/http"
	"testing"
	"time"
)

var mockServerResponse = "mock-svc"

func TestReverseProxy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mockSrv := StartMockServer(ctx)
	defer func() {
		_ = mockSrv.Close()
	}()

	srv := New(&Config{
		Host:    "127.0.0.1",
		Port:    10101,
		TlsPort: 10102,
	})

	srv.RoutingTable = &router.RoutingTable{
		Ingresses:       mocks.IngressMock(),
		TlsCertificates: mocks.TlsCertificatesMock(),
	}

	go func() {
		srv.Run(ctx)
	}()

	waitForServer(ctx, 10101)

	// check if reverse proxy works for http request
	req, err := http.NewRequest("GET", "http://127.0.0.1:10101", nil)
	assert.NoError(t, err)
	req.Host = "www.guardgress.com"

	res, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)
	bs, err := io.ReadAll(res.Body)
	assert.NoError(t, err)
	_ = res.Body.Close()
	assert.Equal(t, mockServerResponse, string(bs))

	// check if reverse proxy works for https request
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	req, err = http.NewRequest("GET", "https://127.0.0.1:10102", nil)
	assert.NoError(t, err)
	req.Host = "www.guardgress.com"

	res, err = http.DefaultClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)
	bs, err = io.ReadAll(res.Body)
	assert.NoError(t, err)
	_ = res.Body.Close()
	assert.Equal(t, mockServerResponse, string(bs))

}

func StartMockServer(ctx context.Context) *http.Server {
	mockSrv := &http.Server{
		Addr: "127.0.0.1:10100",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
