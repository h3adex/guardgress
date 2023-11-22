package models

import "github.com/gospider007/ja3"

type ClientHelloParsed struct {
	NegotiatedProtocol string
	TlsVersion         uint16
	UserAgent          string
	OrderHeaders       []string
	Cookies            string
	Tls                ja3.TlsData
	Ja3                string
	Ja3n               string
	Ja4                string
	Ja4h               string
	/*TODO: any need?
	Http2              ja3.H2Ja3Spec
	AkamaiFp           string*/
}
