package limitHandler

import (
	"context"
	"github.com/h3adex/guardgress/pkg/mocks"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/store/memory"
	"sync"
	"testing"
	"time"
)

func TestLimiterModule5H(t *testing.T) {
	key := "127.0.0.1"
	rateAnnotation := "5-H"
	ctx := context.Background()

	rate, err := limiter.NewRateFromFormatted(rateAnnotation)
	if err != nil {
		panic(err)
	}

	store := memory.NewStore()
	instance := limiter.New(store, rate)

	for i := 1; i <= 10; i++ {
		increment, err := instance.Increment(ctx, key, 1)
		if err != nil {
			log.Error(err.Error())
		}

		if i <= 5 {
			assert.Equal(t, increment.Reached, false)
		} else {
			assert.Equal(t, increment.Reached, true)
		}
	}
}

func TestLimiterModule1S(t *testing.T) {
	key := "127.0.0.1"
	rateAnnotation := "1-S"
	ctx := context.Background()

	rate, err := limiter.NewRateFromFormatted(rateAnnotation)
	if err != nil {
		panic(err)
	}

	store := memory.NewStore()
	instance := limiter.New(store, rate)

	for i := 1; i <= 3; i++ {
		increment, _ := instance.Increment(ctx, key, 1)
		assert.Equal(t, increment.Reached, false)
		time.Sleep(time.Second * 1)
	}

	_, _ = instance.Increment(ctx, key, 1)
	for i := 1; i <= 5; i++ {
		increment, _ := instance.Increment(ctx, key, 1)
		assert.Equal(t, increment.Reached, true)
	}

}

func TestIsIpLimited(t *testing.T) {
	ip := "127.0.0.1"
	ingressExactPathMock := mocks.IngressExactPathTypeMock()
	ingressExactPathMock.Annotations = map[string]string{
		"guardgress/limit-period": "1-S",
	}
	ingressLimiter := GetIngressLimiter(ingressExactPathMock)

	assert.Equal(t, false, IpIsLimited(ingressLimiter, map[string]string{}, ip))
	assert.Equal(t, true, IpIsLimited(ingressLimiter, map[string]string{}, ip))
	assert.Equal(t, false, IpIsLimited(ingressLimiter, map[string]string{
		"guardgress/limit-ip-whitelist": "127.0.0.1",
	}, ip))

}

func TestGetIngressLimiter(t *testing.T) {
	ingressExactPathMock := mocks.IngressExactPathTypeMock()
	ingressExactPathMock.Annotations = map[string]string{
		"guardgress/limit-period": "20-S",
	}
	ingressLimiter := GetIngressLimiter(ingressExactPathMock)
	assert.Equal(t, ingressLimiter.Rate.Limit, int64(20))
	assert.Equal(t, ingressLimiter.Rate.Period, time.Second)

	ingressExactPathMock = mocks.IngressExactPathTypeMock()
	ingressExactPathMock.Annotations = map[string]string{
		"guardgress/limit-period": "20-H",
	}
	ingressLimiter = GetIngressLimiter(ingressExactPathMock)

	assert.Equal(t, ingressLimiter.Rate.Limit, int64(20))
	assert.Equal(t, ingressLimiter.Rate.Period, time.Hour)

	ingressExactPathMock = mocks.IngressExactPathTypeMock()
	ingressExactPathMock.Annotations = map[string]string{}
	ingressLimiter = GetIngressLimiter(ingressExactPathMock)
	assert.Nil(t, ingressLimiter)
}

func TestRateLimitTriggeredRPS1(t *testing.T) {
	mockIp := "127.0.0.1"
	ingressExactPathMock := mocks.IngressExactPathTypeMock()
	ingressExactPathMock.Annotations = map[string]string{
		"guardgress/limit-period": "1-S",
	}
	ingressLimiter := GetIngressLimiter(ingressExactPathMock)
	assert.Equal(t, IpIsLimited(ingressLimiter, ingressExactPathMock.Annotations, mockIp), false)
	assert.Equal(t, IpIsLimited(ingressLimiter, ingressExactPathMock.Annotations, mockIp), true)
	assert.Equal(t, IpIsLimited(ingressLimiter, ingressExactPathMock.Annotations, mockIp), true)
	time.Sleep(time.Second * 1)
	assert.Equal(t, IpIsLimited(ingressLimiter, ingressExactPathMock.Annotations, mockIp), false)
	assert.Equal(t, IpIsLimited(ingressLimiter, ingressExactPathMock.Annotations, mockIp), true)
	time.Sleep(time.Millisecond * 500)
	assert.Equal(t, IpIsLimited(ingressLimiter, ingressExactPathMock.Annotations, mockIp), true)
	time.Sleep(time.Millisecond * 500)
	assert.Equal(t, IpIsLimited(ingressLimiter, ingressExactPathMock.Annotations, mockIp), false)
}

func TestRateLimitTriggeredRPS10(t *testing.T) {
	mockIp := "127.0.0.1"

	// Mocking ingress with the desired limit period
	ingressExactPathMock := mocks.IngressExactPathTypeMock()
	ingressExactPathMock.Annotations = map[string]string{
		"guardgress/limit-period": "50-S",
	}
	ingressLimiter := GetIngressLimiter(ingressExactPathMock)

	const numRequests = 50
	var wg sync.WaitGroup
	wg.Add(numRequests)

	// Simulating multiple requests concurrently
	for i := 0; i < numRequests; i++ {
		go func(wg *sync.WaitGroup) {
			defer wg.Done()
			log.Info("simulating request")
			assert.Equal(t, false, IpIsLimited(ingressLimiter, ingressExactPathMock.Annotations, mockIp))
		}(&wg)
	}
	wg.Wait()

	// The IP should be limited after reaching the specified limit
	assert.Equal(t, true, IpIsLimited(ingressLimiter, ingressExactPathMock.Annotations, mockIp))
}

func TestRateLimitTriggeredRPM10(t *testing.T) {
	mockIp := "127.0.0.1"
	ingressExactPathMock := mocks.IngressExactPathTypeMock()
	ingressExactPathMock.Annotations = map[string]string{
		"guardgress/limit-period": "5-M",
	}
	ingressLimiter := GetIngressLimiter(ingressExactPathMock)

	// range 10
	for i := 1; i <= 10; i++ {
		if i <= 5 {
			assert.Equal(t, IpIsLimited(ingressLimiter, ingressExactPathMock.Annotations, mockIp), false)
		} else {
			assert.Equal(t, IpIsLimited(ingressLimiter, ingressExactPathMock.Annotations, mockIp), true)
		}

	}

}
