package models

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/gospider007/ja3"
	"github.com/gospider007/requests"
	"github.com/h3adex/guardgress/pkg/algorithms"
)

type ParsedClientHello struct {
	NegotiatedProtocol string
	TlsVersion         uint16
	UserAgent          string
	OrderHeaders       []string
	Cookies            string
	Tls                ja3.TlsData
	Ja3                string
	Ja3n               string
	Ja3H               string
	Ja4                string
	Ja4h               string
}

func ParseClientHello(ctx *gin.Context) (ParsedClientHello, error) {
	fpData, ok := ja3.GetFpContextData(ctx.Request.Context())
	connectionState := fpData.ConnectionState()

	result := ParsedClientHello{
		NegotiatedProtocol: connectionState.NegotiatedProtocol,
		TlsVersion:         connectionState.Version,
		UserAgent:          ctx.Request.UserAgent(),
		OrderHeaders:       fpData.OrderHeaders(),
		Cookies:            requests.Cookies(ctx.Request.Cookies()).String(),
		Tls:                ja3.TlsData{},
		Ja3:                "",
		Ja3n:               "",
		Ja3H:               "",
		Ja4:                "",
		Ja4h:               "",
	}

	tlsData, err := fpData.TlsData()
	if err == nil {
		result.Tls = tlsData
		result.Ja3, result.Ja3n = tlsData.Fp()
		result.Ja3H = algorithms.Ja3Digest(result.Ja3)
		result.Ja4 = tlsData.Ja4()
		result.Ja4h = fpData.Ja4H(ctx.Request)
	}

	if ok {
		return result, nil
	}

	return result, fmt.Errorf("unable to fingerprint tls handshake")
}
