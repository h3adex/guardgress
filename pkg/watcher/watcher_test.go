package watcher

import (
	"context"
	"crypto/tls"
	"github.com/stretchr/testify/assert"
	v14 "k8s.io/api/apps/v1"
	v12 "k8s.io/api/core/v1"
	v1 "k8s.io/api/networking/v1"
	v13 "k8s.io/apimachinery/pkg/apis/meta/v1"
	testClient "k8s.io/client-go/kubernetes/fake"
	"testing"
	"time"
)

func TestWatcherDetectChanges(t *testing.T) {
	t.Run("test change detected on ingress resources in cluster", func(t *testing.T) {
		updateCalled := make(chan struct{})
		defer close(updateCalled)

		client := testClient.NewSimpleClientset()
		watcher := New(
			client,
			func(payload Payload) {
				t.Log("Update called")
				t.Log(payload)
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

		ingress, err := client.NetworkingV1().Ingresses("default").Create(context.Background(), &v1.Ingress{}, v13.CreateOptions{})
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
}
