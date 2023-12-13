package main

import (
	"context"
	"github.com/caarlos0/env"
	"github.com/h3adex/guardgress/pkg/server"
	"github.com/h3adex/guardgress/pkg/watcher"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"os"
	"path/filepath"
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
	k8sClient, err := kubernetes.NewForConfig(getKubernetesConfig())
	if err != nil {
		log.Panic(err)
	}

	config := &server.Config{}
	if err = env.Parse(config); err != nil {
		log.Panic(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	eg, ctx := errgroup.WithContext(ctx)
	srv := server.New(config)

	eg.Go(func() error {
		return srv.Run(ctx)
	})

	eg.Go(func() error {
		return watcher.New(k8sClient, func(routingTable watcher.Payload) {
			srv.UpdateRoutingTable(routingTable)
		}).Run(ctx)
	})

	if err = eg.Wait(); err != nil {
		log.Error("Error on watcher or server goroutine: ", err.Error())
		log.Panic(err)
	}
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
	if home := os.Getenv("HOME"); home != "" {
		return home
	}

	// windows
	return os.Getenv("USERPROFILE")
}
