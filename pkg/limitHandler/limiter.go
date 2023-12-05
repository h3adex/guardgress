package limitHandler

import (
	"context"
	"errors"
	"github.com/h3adex/guardgress/pkg/annotations"
	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/store/memory"
	v1 "k8s.io/api/networking/v1"
)

// TODO: use this error
var ErrAnnotationNotFound = errors.New("guardgress/limit-period annotation not found")

func GetIngressLimiter(ingress v1.Ingress) *limiter.Limiter {
	ingressAnnotations := ingress.Annotations
	if ingressAnnotations == nil {
		return nil
	}

	limitAnnotation := ingressAnnotations[annotations.LimitPeriod]
	if len(limitAnnotation) > 0 {
		rate, err := limiter.NewRateFromFormatted(limitAnnotation)
		if err != nil {
			// log error or handle it appropriately
			return nil
		}
		return limiter.New(memory.NewStore(), rate)
	}

	return nil
}

func IpIsLimited(ingressLimiter *limiter.Limiter, ingressAnnotations map[string]string, ip string) bool {
	if ingressLimiter == nil {
		return false
	}

	if annotations.IsIpWhitelisted(ingressAnnotations, ip) {
		return false
	}

	// TODO: learn more about context.TODO()
	increment, err := ingressLimiter.Increment(context.TODO(), ip, 1)
	if err != nil {
		// log_error
		return true
	}

	return increment.Reached
}
