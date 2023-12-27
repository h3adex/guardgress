package watcher

import (
	"context"
	"crypto/tls"
	"github.com/bep/debounce"
	"github.com/h3adex/guardgress/pkg/limithandler"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"github.com/ulule/limiter/v3"
	"k8s.io/api/networking/v1"
	v12 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"sync"
	"time"
)

var ingressClassName = "guardgress"

type Payload struct {
	Ingresses       *v1.IngressList
	TlsCertificates map[string]*tls.Certificate
	IngressLimiters []*limiter.Limiter
}

type Watcher struct {
	Client       kubernetes.Interface
	UpdateServer func(payload Payload)
}

var (
	ingressesGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "watcher_ingresses_total",
		Help: "Total number of ingresses",
	})
	ingressLimitersGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "watcher_ingress_limiters_total",
		Help: "Total number of ingress limiters",
	})
	tlsCertificatesGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "watcher_tls_certificates_total",
		Help: "Total number of TLS certificates",
	})
)

func init() {
	prometheus.MustRegister(ingressesGauge, ingressLimitersGauge, tlsCertificatesGauge)
}

func New(
	client kubernetes.Interface,
	updateServer func(payload Payload),
) *Watcher {
	return &Watcher{
		Client:       client,
		UpdateServer: updateServer,
	}
}

func (p *Payload) countIngressLimiters() float64 {
	var count float64 = 0
	for _, ingress := range p.IngressLimiters {
		if ingress == nil {
			continue
		}
		count++
	}

	return count
}

func (w *Watcher) onChange() {
	log.Debug("Updating routing table")

	ingresses, err := listIngresses(w.Client)
	if err != nil {
		log.Error("unable to get k8s ingresses: ", err.Error())
	}

	payload := Payload{
		TlsCertificates: map[string]*tls.Certificate{},
		Ingresses:       ingresses,
	}

	for _, ingress := range ingresses.Items {
		if ingress.Spec.TLS == nil {
			continue
		}

		ingressLimiters := limithandler.GetIngressLimiter(ingress)
		payload.IngressLimiters = append(payload.IngressLimiters, ingressLimiters)

		for _, tlsCert := range ingress.Spec.TLS {
			if tlsCert.SecretName == "" {
				continue
			}

			secret, err := w.Client.CoreV1().Secrets(ingress.Namespace).Get(context.Background(), tlsCert.SecretName, v12.GetOptions{})
			if err != nil {
				log.Error("getting secrets: ", err.Error())
				continue
			}

			cert, err := tls.X509KeyPair(secret.Data["tls.crt"], secret.Data["tls.key"])
			if err != nil {
				log.Error("creating x509 key pair: ", err.Error())
			}

			for _, host := range tlsCert.Hosts {
				payload.TlsCertificates[host] = &cert
			}
		}
	}

	ingressesGauge.Set(float64(len(ingresses.Items)))
	ingressLimitersGauge.Set(payload.countIngressLimiters())
	tlsCertificatesGauge.Set(float64(len(payload.TlsCertificates)))

	w.UpdateServer(payload)
}

func (w *Watcher) Run(ctx context.Context) error {
	log.Info("Starting Watcher")
	factory := informers.NewSharedInformerFactory(w.Client, time.Minute)
	debounced := debounce.New(time.Second)
	handler := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			debounced(func() {
				w.onChange()
			})
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			debounced(func() {
				w.onChange()
			})
		},
		DeleteFunc: func(obj interface{}) {
			debounced(func() {
				w.onChange()
			})
		},
	}
	wg := sync.WaitGroup{}

	wg.Add(1)
	go func() {
		secretInformer := factory.Core().V1().Secrets().Informer()
		_, err := secretInformer.AddEventHandler(handler)
		if err != nil {
			log.Error("unable to add secret informer: ", err.Error())
		}
		secretInformer.Run(ctx.Done())
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		ingressInformer := factory.Networking().V1().Ingresses().Informer()
		_, err := ingressInformer.AddEventHandler(handler)
		if err != nil {
			log.Error("unable to add ingress informer: ", err.Error())
		}
		ingressInformer.Run(ctx.Done())
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		serviceInformer := factory.Core().V1().Services().Informer()
		_, err := serviceInformer.AddEventHandler(handler)
		if err != nil {
			log.Error("unable to add service informer: ", err.Error())
		}
		serviceInformer.Run(ctx.Done())
		wg.Done()
	}()

	return nil
}

// listIngresses returns a list of ingresses filtered by ingressClassName
func listIngresses(client kubernetes.Interface) (*v1.IngressList, error) {
	// List all ingresses
	allIngresses, err := client.NetworkingV1().Ingresses("").List(context.TODO(), v12.ListOptions{})
	if err != nil {
		return nil, err
	}

	filteredIngresses := &v1.IngressList{}

	// Filter ingresses based on ingressClassName
	for _, ingress := range allIngresses.Items {
		if ingress.Spec.IngressClassName == nil || *ingress.Spec.IngressClassName == ingressClassName {
			filteredIngresses.Items = append(filteredIngresses.Items, ingress)
		}
	}

	return filteredIngresses, nil
}
