package main

import (
	"context"
	"github.com/caarlos0/env"
	"github.com/h3adex/guardgress/pkg/server"
	"github.com/h3adex/guardgress/pkg/watcher"
	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"os"
	"path/filepath"
	"sync"
)

func init() {
	logLevel, ok := os.LookupEnv("LOG_LEVEL")
	// LOG_LEVEL not set, let's default to info
	if !ok {
		logLevel = "info"
	}

	level, err := log.ParseLevel(logLevel)
	if err != nil {
		log.Error("failed to parse LOG_LEVEL, defaulting to info")
		log.SetLevel(log.InfoLevel)
		return
	}

	log.SetLevel(level)
}

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

	w := watcher.New(k8sClient, func(routingTable watcher.Payload) {
		srv.UpdateRoutingTable(routingTable)
	})

	wg.Add(1)
	go func() {
		defer wg.Done()
		srv.Run()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		err := w.Run(ctx)
		if err != nil {
			return
		}
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
