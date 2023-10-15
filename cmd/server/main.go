package main

import (
	"context"
	"github.com/caarlos0/env"
	"github.com/h3adex/phalanx/pkg/server"
	"github.com/h3adex/phalanx/pkg/watcher"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"log"
	"os"
	"path/filepath"
	"sync"
)

func main() {
	wg := sync.WaitGroup{}
	ctx := context.Background()
	k8sClient, err := kubernetes.NewForConfig(getKubernetesConfig())

	if err != nil {
		log.Fatalln(err)
	}

	config := &server.Config{}

	if err := env.Parse(config); err != nil {
		log.Fatalln(err)
	}
	srv := server.New(config)

	// Monkey patch that hoe
	/*srv.RoutingTable.GetTlsCertificate()*/

	w := watcher.New(k8sClient, func(routingTable watcher.Payload) {
		srv.UpdateRoutingTable(routingTable)
	})

	wg.Add(1)
	go func() {
		defer wg.Done()
		srv.Run(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		w.Run(ctx)
	}()

	wg.Wait()
}

func getKubernetesConfig() *rest.Config {
	config, err := rest.InClusterConfig()
	if err != nil {
		config, err = clientcmd.BuildConfigFromFlags("", filepath.Join(getHomeDir(), ".kube", "config"))
	}
	if err != nil {
		log.Fatalln(err)
	}
	return config
}

func getHomeDir() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	return os.Getenv("USERPROFILE") // windows
}
