package watcher

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/h3adex/guardgress/pkg/healthmetrics"
	"github.com/stretchr/testify/assert"
	"io"
	v14 "k8s.io/api/apps/v1"
	v12 "k8s.io/api/core/v1"
	v1 "k8s.io/api/networking/v1"
	v13 "k8s.io/apimachinery/pkg/apis/meta/v1"
	testClient "k8s.io/client-go/kubernetes/fake"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

var nginxIngressClassName = "nginx"

func TestWatcherDetectChanges(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		err := healthmetrics.New().Run(ctx)
		assert.NoError(t, err)
	}()

	waitForServer(ctx, 10254)

	t.Run("test change detected on ingress resources in cluster with ingressClassName guardgress", func(t *testing.T) {
		updateCalled := make(chan struct{})
		defer close(updateCalled)

		client := testClient.NewSimpleClientset()
		watcher := New(
			client,
			func(payload Payload) {
				t.Log("Update called")
				assert.True(t, payload.Ingresses.Items[0].Name == "test-ingress")
				updateCalled <- struct{}{}
			},
		)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go func() {
			if err := watcher.Run(ctx); err != nil {
				t.Errorf("Watcher Run function error: %v", err)
			}
		}()

		ingress, err := client.NetworkingV1().Ingresses("default").Create(context.Background(), &v1.Ingress{
			TypeMeta: v13.TypeMeta{},
			ObjectMeta: v13.ObjectMeta{
				Name: "test-ingress",
			},
			Spec: v1.IngressSpec{
				IngressClassName: &ingressClassName,
			},
			Status: v1.IngressStatus{},
		}, v13.CreateOptions{})
		if err != nil {
			t.Errorf("Error creating ingress: %v", err)
		}

		select {
		case <-updateCalled:
			t.Logf("Update called after creating ingress: %s", ingress.Name)
		case <-time.After(5 * time.Second): // Adjust the timeout according to your test scenario
			t.Error("Update not triggered within the expected time")
		}
	})

	t.Run("test change detected on ingress resources in cluster without ingressClassName", func(t *testing.T) {
		updateCalled := make(chan struct{})
		defer close(updateCalled)

		client := testClient.NewSimpleClientset()
		watcher := New(
			client,
			func(payload Payload) {
				t.Log("Update called")
				assert.True(t, payload.Ingresses.Items[0].Name == "test-ingress")
				updateCalled <- struct{}{}
			},
		)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go func() {
			if err := watcher.Run(ctx); err != nil {
				t.Errorf("Watcher Run function error: %v", err)
			}
		}()

		ingress, err := client.NetworkingV1().Ingresses("default").Create(context.Background(), &v1.Ingress{
			TypeMeta: v13.TypeMeta{},
			ObjectMeta: v13.ObjectMeta{
				Name: "test-ingress",
			},
			Status: v1.IngressStatus{},
		}, v13.CreateOptions{})
		if err != nil {
			t.Errorf("Error creating ingress: %v", err)
		}

		select {
		case <-updateCalled:
			t.Logf("Update called after creating ingress: %s", ingress.Name)
		case <-time.After(5 * time.Second): // Adjust the timeout according to your test scenario
			t.Error("Update not triggered within the expected time")
		}
	})

	t.Run("test change detected on ingress resources in cluster but with false ingressClassName", func(t *testing.T) {
		updateCalled := make(chan struct{})
		defer close(updateCalled)

		client := testClient.NewSimpleClientset()
		watcher := New(
			client,
			func(payload Payload) {
				t.Log("Update called")
				// ingress should not be in the payload since it has a different className
				assert.True(t, len(payload.Ingresses.Items) == 0)
				updateCalled <- struct{}{}
			},
		)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go func() {
			if err := watcher.Run(ctx); err != nil {
				t.Errorf("Watcher Run function error: %v", err)
			}
		}()

		ingress, err := client.NetworkingV1().Ingresses("default").Create(context.Background(), &v1.Ingress{
			TypeMeta: v13.TypeMeta{},
			ObjectMeta: v13.ObjectMeta{
				Name: "test-ingress",
			},
			Spec: v1.IngressSpec{
				IngressClassName: &nginxIngressClassName,
			},
			Status: v1.IngressStatus{},
		}, v13.CreateOptions{})
		if err != nil {
			t.Errorf("Error creating ingress: %v", err)
		}

		select {
		case <-updateCalled:
			t.Logf("Update called after creating ingress: %s", ingress.Name)
		case <-time.After(5 * time.Second): // Adjust the timeout according to your test scenario
			t.Error("Update not triggered within the expected time")
		}
	})

	t.Run("test change detected on service resources in cluster", func(t *testing.T) {
		updateCalled := make(chan struct{})
		defer close(updateCalled)

		client := testClient.NewSimpleClientset()
		watcher := New(
			client,
			func(payload Payload) {
				updateCalled <- struct{}{}
			},
		)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go func() {
			if err := watcher.Run(ctx); err != nil {
				t.Errorf("Watcher Run function error: %v", err)
			}
		}()

		service, err := client.CoreV1().Services("default").Create(context.Background(), &v12.Service{}, v13.CreateOptions{})
		if err != nil {
			t.Errorf("Error creating service: %v", err)
		}

		select {
		case <-updateCalled:
			t.Logf("Update called after creating service: %s", service.Name)
		case <-time.After(5 * time.Second): // Adjust the timeout according to your test scenario
			t.Error("Update not triggered within the expected time")
		}
	})

	t.Run("test change detected on secret resources in cluster", func(t *testing.T) {
		updateCalled := make(chan struct{})
		defer close(updateCalled)

		client := testClient.NewSimpleClientset()
		watcher := New(
			client,
			func(payload Payload) {
				updateCalled <- struct{}{}
			},
		)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go func() {
			if err := watcher.Run(ctx); err != nil {
				t.Errorf("Watcher Run function error: %v", err)
			}
		}()

		secret, err := client.CoreV1().Secrets("default").Create(context.Background(), &v12.Secret{}, v13.CreateOptions{})
		if err != nil {
			t.Errorf("Error creating secret: %v", err)
		}

		select {
		case <-updateCalled:
			t.Logf("Update called after creating secret: %s", secret.Name)
		case <-time.After(5 * time.Second): // Adjust the timeout according to your test scenario
			t.Error("Update not triggered within the expected time")
		}
	})

	t.Run("test change detected on daemonset resources in cluster", func(t *testing.T) {
		updateCalled := make(chan struct{})
		defer close(updateCalled)

		client := testClient.NewSimpleClientset()
		watcher := New(
			client,
			func(payload Payload) {
				updateCalled <- struct{}{}
			},
		)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go func() {
			if err := watcher.Run(ctx); err != nil {
				t.Errorf("Watcher Run function error: %v", err)
			}
		}()

		ds, err := client.AppsV1().DaemonSets("default").Create(context.Background(), &v14.DaemonSet{}, v13.CreateOptions{})
		if err != nil {
			t.Errorf("Error creating ds: %v", err)
		}

		select {
		case <-updateCalled:
			// should not be called
			t.Errorf("Update called after creating ds: %s", ds.Name)
		case <-time.After(5 * time.Second):
			t.Logf("Update successfully not triggered within the expected time")
		}
	})

	t.Run("test if routing-table update works for ingress resources", func(t *testing.T) {
		routingChannel := make(chan Payload)
		defer close(routingChannel)

		client := testClient.NewSimpleClientset()
		watcher := New(
			client,
			func(payload Payload) {
				routingChannel <- Payload{
					Ingresses: &v1.IngressList{
						Items: []v1.Ingress{
							{
								ObjectMeta: v13.ObjectMeta{
									Name: "TestIngress",
								},
							},
						},
					},
					TlsCertificates: map[string]*tls.Certificate{},
					IngressLimiters: nil,
				}
			},
		)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		if err := watcher.Run(ctx); err != nil {
			t.Errorf("Watcher Run function error: %v", err)
		}

		_, err := client.CoreV1().Secrets("default").Create(context.Background(), &v12.Secret{}, v13.CreateOptions{})
		if err != nil {
			t.Errorf("Error creating secret: %v", err)
		}

		select {
		case receivedPayload := <-routingChannel:
			assert.True(t, receivedPayload.Ingresses.Items[0].Name == "TestIngress")
			t.Logf("Update signal received with payload: %+v", receivedPayload)
		case <-time.After(5 * time.Second): // Adjust timeout if needed
			t.Error("Update not received within the expected time")
		}
	})

	t.Run("test if watcher metrics are registered", func(t *testing.T) {
		// check if metrics are working
		res, err := http.Get("http://0.0.0.0:10254/metrics")
		assert.NoError(t, err)
		assert.Equal(t, 200, res.StatusCode)
		bs, err := io.ReadAll(res.Body)
		t.Log(string(bs))
		assert.NoError(t, err)

		metricsWhichShouldBePresent := []string{
			"watcher_ingresses_total",
			"watcher_ingress_limiters_total",
			"watcher_tls_certificates_total",
		}

		for _, metric := range metricsWhichShouldBePresent {
			t.Run("test if metric "+metric+" is present", func(t *testing.T) {
				assert.True(t, strings.ContainsAny(string(bs), metric))
			})
		}
	})
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
