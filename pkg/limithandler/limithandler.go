package limithandler

import (
	"context"
	"fmt"
	"github.com/h3adex/guardgress/pkg/annotations"
	"github.com/redis/go-redis/v9"
	log "github.com/sirupsen/logrus"
	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/store/memory"
	redisStore "github.com/ulule/limiter/v3/drivers/store/redis"
	v1 "k8s.io/api/networking/v1"
	"strings"
	"time"
)

func GetIngressLimiter(ingress v1.Ingress) *limiter.Limiter {
	ingressAnnotations := ingress.Annotations
	if ingressAnnotations == nil {
		return nil
	}

	limitPeriodAnnotation := ingressAnnotations[annotations.LimitPeriod]
	limitRedisStoreAnnotation := ingressAnnotations[annotations.LimitRedisStore]

	if len(limitPeriodAnnotation) <= 0 {
		return nil
	}

	rate, err := limiter.NewRateFromFormatted(limitPeriodAnnotation)
	if err != nil {
		log.Error("failed to parse rate: ", err.Error())
		return nil
	}

	if len(limitRedisStoreAnnotation) <= 0 {
		return limiter.New(memory.NewStore(), rate)
	}

	redisClient, err := GetRedisClient(limitRedisStoreAnnotation)
	if err != nil {
		log.Fatalln(err.Error())
	}

	store, err := redisStore.NewStoreWithOptions(
		redisClient,
		limiter.StoreOptions{},
	)

	if err != nil {
		log.Fatal("failed to create redis store: ", err.Error())
	}

	return limiter.New(store, rate)
}

func GetRedisClient(redisUrl string) (*redis.Client, error) {
	if !strings.HasPrefix(redisUrl, "redis://") {
		return nil, fmt.Errorf("redis url must start with redis://")
	}

	option, err := redis.ParseURL(redisUrl)
	if err != nil {
		return nil, fmt.Errorf("unable to parse provided redis url: %s", err.Error())
	}

	return redis.NewClient(option), nil
}

func IsLimited(ingressLimiter *limiter.Limiter, ingressAnnotations map[string]string, ip, path string) bool {
	if ingressLimiter == nil {
		return false
	}

	if annotations.IsIpWhitelisted(ingressAnnotations, ip) {
		return false
	}

	if annotations.IsPathWhiteListed(ingressAnnotations, path) {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()

	increment, err := ingressLimiter.Increment(ctx, ip, 1)
	if err != nil {
		log.Error("failed to increment limiter: ", err.Error())
		return true
	}

	return increment.Reached
}
