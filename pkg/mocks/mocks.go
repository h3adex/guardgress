package mocks

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/networking/v1"
	v12 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"math/big"
	"time"
)

var pathTypeExact = v1.PathTypeExact
var pathTypePrefix = v1.PathTypePrefix
var pathTypeImplementationSpecific = v1.PathTypeImplementationSpecific

func IngressExactPathTypeMock() v1.Ingress {
	return v1.Ingress{
		ObjectMeta: v12.ObjectMeta{
			Namespace: "default",
		},
		Spec: v1.IngressSpec{
			IngressClassName: nil,
			DefaultBackend:   nil,
			TLS:              nil,
			Rules: []v1.IngressRule{
				{
					Host: "www.guardgress.com",
					IngressRuleValue: v1.IngressRuleValue{
						HTTP: &v1.HTTPIngressRuleValue{
							Paths: []v1.HTTPIngressPath{
								{
									Path:     "/",
									PathType: &pathTypeExact,
									Backend: v1.IngressBackend{
										Service: &v1.IngressServiceBackend{
											Name: "127.0.0.1",
											Port: v1.ServiceBackendPort{
												Name:   "",
												Number: 10100,
											},
										},
										Resource: nil,
									},
								},
							},
						},
					},
				},
			},
		},
		Status: v1.IngressStatus{},
	}
}

func IngressPathTypePrefixMock() v1.Ingress {
	return v1.Ingress{
		TypeMeta: v12.TypeMeta{},
		ObjectMeta: v12.ObjectMeta{
			Namespace: "default",
		},
		Spec: v1.IngressSpec{
			IngressClassName: nil,
			DefaultBackend:   nil,
			TLS:              nil,
			Rules: []v1.IngressRule{
				{
					Host: "www.guardgress.com",
					IngressRuleValue: v1.IngressRuleValue{
						HTTP: &v1.HTTPIngressRuleValue{
							Paths: []v1.HTTPIngressPath{
								{
									Path:     "/foo",
									PathType: &pathTypePrefix,
									Backend: v1.IngressBackend{
										Service: &v1.IngressServiceBackend{
											Name: "127.0.0.1",
											Port: v1.ServiceBackendPort{
												Name:   "",
												Number: 10100,
											},
										},
										Resource: nil,
									},
								},
							},
						},
					},
				},
			},
		},
		Status: v1.IngressStatus{},
	}
}

func IngressPathTypeImplementationSpecificTypeMock() v1.Ingress {
	return v1.Ingress{
		TypeMeta: v12.TypeMeta{},
		ObjectMeta: v12.ObjectMeta{
			Namespace: "default",
		},
		Spec: v1.IngressSpec{
			IngressClassName: nil,
			DefaultBackend:   nil,
			TLS:              nil,
			Rules: []v1.IngressRule{
				{
					Host: "www.guardgress.com",
					IngressRuleValue: v1.IngressRuleValue{
						HTTP: &v1.HTTPIngressRuleValue{
							Paths: []v1.HTTPIngressPath{
								{
									Path:     "/foo",
									PathType: &pathTypeImplementationSpecific,
									Backend: v1.IngressBackend{
										Service: &v1.IngressServiceBackend{
											Name: "127.0.0.1",
											Port: v1.ServiceBackendPort{
												Name:   "",
												Number: 10100,
											},
										},
										Resource: nil,
									},
								},
							},
						},
					},
				},
			},
		},
		Status: v1.IngressStatus{},
	}
}

func IngressNoPathTypeMock() v1.Ingress {
	return v1.Ingress{
		TypeMeta: v12.TypeMeta{},
		ObjectMeta: v12.ObjectMeta{
			Namespace: "default",
		},
		Spec: v1.IngressSpec{
			IngressClassName: nil,
			DefaultBackend:   nil,
			TLS:              nil,
			Rules: []v1.IngressRule{
				{
					Host: "www.guardgress.com",
					IngressRuleValue: v1.IngressRuleValue{
						HTTP: &v1.HTTPIngressRuleValue{
							Paths: []v1.HTTPIngressPath{
								{
									Path:     "/",
									PathType: nil,
									Backend: v1.IngressBackend{
										Service: &v1.IngressServiceBackend{
											Name: "127.0.0.1",
											Port: v1.ServiceBackendPort{
												Name:   "",
												Number: 10100,
											},
										},
										Resource: nil,
									},
								},
							},
						},
					},
				},
			},
		},
		Status: v1.IngressStatus{},
	}
}

func IngressJenkinsMock() v1.Ingress {
	return v1.Ingress{
		TypeMeta: v12.TypeMeta{},
		ObjectMeta: v12.ObjectMeta{
			Namespace: "default",
		},
		Spec: v1.IngressSpec{
			IngressClassName: nil,
			DefaultBackend:   nil,
			TLS:              nil,
			Rules: []v1.IngressRule{
				{
					Host: "jenkins.guardgress.com",
					IngressRuleValue: v1.IngressRuleValue{
						HTTP: &v1.HTTPIngressRuleValue{
							Paths: []v1.HTTPIngressPath{
								{
									PathType: &pathTypeImplementationSpecific,
									Backend: v1.IngressBackend{
										Service: &v1.IngressServiceBackend{
											Name: "jenkins",
											Port: v1.ServiceBackendPort{
												Name:   "",
												Number: 8080,
											},
										},
										Resource: nil,
									},
								},
								{
									Path:     "/wsagents",
									PathType: &pathTypeImplementationSpecific,
									Backend: v1.IngressBackend{
										Service: &v1.IngressServiceBackend{
											Name: "jenkins-wssocket",
											Port: v1.ServiceBackendPort{
												Name:   "",
												Number: 8080,
											},
										},
										Resource: nil,
									},
								},
								{
									Path:     "/github-webhook/",
									PathType: &pathTypeImplementationSpecific,
									Backend: v1.IngressBackend{
										Service: &v1.IngressServiceBackend{
											Name: "jenkins-webhook",
											Port: v1.ServiceBackendPort{
												Name:   "",
												Number: 8080,
											},
										},
										Resource: nil,
									},
								},
							},
						},
					},
				},
			},
		},
		Status: v1.IngressStatus{},
	}

}

func SelfSignedCertMock() (*tls.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Mock Certificate"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privateKey,
	}

	return &cert, nil
}

func TlsCertificatesMock() map[string]*tls.Certificate {
	cert, err := SelfSignedCertMock()
	if err != nil {
		log.Error("unable to provide self signed cert")

		return map[string]*tls.Certificate{
			"www.guardgress.com": {
				Certificate: nil,
				PrivateKey:  nil,
			},
		}
	}

	return map[string]*tls.Certificate{
		"www.guardgress.com": {
			Certificate: nil,
			PrivateKey:  nil,
		},
		"127.0.0.1": cert,
		// needed for https test. Turns out client hello servername is ""
		"": cert,
	}
}
