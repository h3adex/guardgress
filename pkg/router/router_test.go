package router

import (
	"github.com/h3adex/guardgress/internal/crypto/tls"
	"github.com/h3adex/guardgress/pkg/mocks"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGetTlsCertificate(t *testing.T) {
	routingTable := RoutingTable{
		Ingresses:       mocks.IngressMock(),
		TlsCertificates: mocks.TlsCertificatesMock(),
	}
	certificate, err := routingTable.GetTlsCertificate("www.guardgress.com")
	assert.NoError(t, err)
	assert.Equal(t, certificate, &tls.Certificate{Certificate: nil, PrivateKey: nil})
}

func TestGetBackend(t *testing.T) {
	routingTable := RoutingTable{
		Ingresses:       mocks.IngressMock(),
		TlsCertificates: mocks.TlsCertificatesMock(),
	}

	url, _, err := routingTable.GetBackend("www.guardgress.com", "/")
	assert.NoError(t, err)
	assert.Equal(t, url.Host, "127.0.0.1:10100")

	url, _, err = routingTable.GetBackend("www.guardgress.com", "/foo/bar")
	assert.NoError(t, err)
	assert.Equal(t, url.Host, "127.0.0.1:20100")

	url, _, err = routingTable.GetBackend("example.guardgress.com", "/foo/bar")
	assert.NoError(t, err)
	assert.Equal(t, url.Host, "127.0.0.1:30100")

	url, _, err = routingTable.GetBackend("example2.guardgress.com", "/")
	assert.NoError(t, err)
	assert.Equal(t, url.Host, "127.0.0.1:40100")
}
