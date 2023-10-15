package mocks

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/h3adex/phalanx/internal/crypto/tls"
	v1 "k8s.io/api/networking/v1"
	v12 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"log"
	"math/big"
	"time"
)

func IngressMock() *v1.IngressList {
	// pathTypeImplementationSpecific := v1.PathTypeImplementationSpecific
	pathTypeExact := v1.PathTypeExact
	pathTypePrefix := v1.PathTypePrefix

	return &v1.IngressList{
		TypeMeta: v12.TypeMeta{
			Kind:       "",
			APIVersion: "",
		},
		Items: []v1.Ingress{
			{
				ObjectMeta: v12.ObjectMeta{
					Name:                       "",
					GenerateName:               "",
					Namespace:                  "",
					UID:                        "",
					ResourceVersion:            "",
					Generation:                 0,
					CreationTimestamp:          v12.Time{},
					DeletionTimestamp:          nil,
					DeletionGracePeriodSeconds: nil,
					Labels:                     nil,
					Annotations: map[string]string{
						"phalanx/add-ja3-header": "true",
						"phalanx/tls-blacklist":  "d41d8cd98f00b204e9800998ecf8427a",
					},
					OwnerReferences: nil,
					Finalizers:      nil,
					ManagedFields:   nil,
				},
				Spec: v1.IngressSpec{
					IngressClassName: nil,
					DefaultBackend:   nil,
					TLS:              nil,
					Rules: []v1.IngressRule{
						{
							Host: "www.phalanx.com",
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
			},
			{
				TypeMeta:   v12.TypeMeta{},
				ObjectMeta: v12.ObjectMeta{},
				Spec: v1.IngressSpec{
					IngressClassName: nil,
					DefaultBackend:   nil,
					TLS:              nil,
					Rules: []v1.IngressRule{
						{
							Host: "www.phalanx.com",
							IngressRuleValue: v1.IngressRuleValue{
								HTTP: &v1.HTTPIngressRuleValue{
									Paths: []v1.HTTPIngressPath{
										{
											Path:     "/",
											PathType: &pathTypePrefix,
											Backend: v1.IngressBackend{
												Service: &v1.IngressServiceBackend{
													Name: "127.0.0.1",
													Port: v1.ServiceBackendPort{
														Name:   "",
														Number: 20100,
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
			},
			{
				TypeMeta:   v12.TypeMeta{},
				ObjectMeta: v12.ObjectMeta{},
				Spec: v1.IngressSpec{
					IngressClassName: nil,
					DefaultBackend:   nil,
					TLS:              nil,
					Rules: []v1.IngressRule{
						{
							Host: "example.phalanx.com",
							IngressRuleValue: v1.IngressRuleValue{
								HTTP: &v1.HTTPIngressRuleValue{
									Paths: []v1.HTTPIngressPath{
										{
											Path:     "/",
											PathType: &pathTypePrefix,
											Backend: v1.IngressBackend{
												Service: &v1.IngressServiceBackend{
													Name: "127.0.0.1",
													Port: v1.ServiceBackendPort{
														Name:   "",
														Number: 30100,
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
			},
			{
				TypeMeta:   v12.TypeMeta{},
				ObjectMeta: v12.ObjectMeta{},
				Spec: v1.IngressSpec{
					IngressClassName: nil,
					DefaultBackend:   nil,
					TLS:              nil,
					Rules: []v1.IngressRule{
						{
							Host: "example2.phalanx.com",
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
														Number: 40100,
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
			},
		},
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
		log.Println("unable to provide self signed cert")

		return map[string]*tls.Certificate{
			"www.phalanx.com": {
				Certificate: nil,
				PrivateKey:  nil,
			},
		}
	}

	return map[string]*tls.Certificate{
		"www.phalanx.com": {
			Certificate: nil,
			PrivateKey:  nil,
		},
		"127.0.0.1": cert,
		// needed for https test. Turns out client hello servername is ""
		"": cert,
	}
}
