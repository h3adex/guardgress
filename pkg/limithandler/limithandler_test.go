package limithandler

import (
	"context"
	"github.com/h3adex/guardgress/pkg/mocks"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/store/memory"
	"strings"
	"sync"
	"testing"
	"time"
)

func init() {
	log.SetLevel(log.DebugLevel)
}

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

	t.Run("test 1 request in 5H Period limiter raw", func(t *testing.T) {
		for i := 1; i <= 10; i++ {
			increment, err := instance.Increment(ctx, key, 1)
			if err != nil {
				log.Error(err.Error())
			}

			if i <= 5 {
				assert.False(t, increment.Reached)
			} else {
				assert.True(t, increment.Reached)
			}
		}
	})
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

	t.Run("test 1 request in 1S Period limiter raw", func(t *testing.T) {
		for i := 1; i <= 3; i++ {
			increment, _ := instance.Increment(ctx, key, 1)
			assert.False(t, increment.Reached)
			time.Sleep(time.Second * 1)
		}

		_, _ = instance.Increment(ctx, key, 1)
		for i := 1; i <= 5; i++ {
			increment, _ := instance.Increment(ctx, key, 1)
			assert.True(t, increment.Reached)
		}
	})

}

func TestIsIpLimited(t *testing.T) {
	ip := "127.0.0.1"
	ingressExactPathMock := mocks.IngressExactPathTypeMock()
	ingressExactPathMock.Annotations = map[string]string{
		"guardgress/limit-period": "1-S",
	}
	ingressLimiter := GetIngressLimiter(ingressExactPathMock)

	t.Run("test 1 request in 1S Period", func(t *testing.T) {
		assert.False(t, IsLimited(ingressLimiter, map[string]string{}, ip, ""))
		assert.True(t, IsLimited(ingressLimiter, map[string]string{}, ip, ""))
		assert.False(t, IsLimited(ingressLimiter, map[string]string{
			"guardgress/limit-ip-whitelist": "127.0.0.1",
		}, ip, ""))
	})
}

func TestGetIngressLimiter(t *testing.T) {
	ingressExactPathMock := mocks.IngressExactPathTypeMock()
	ingressExactPathMock.Annotations = map[string]string{
		"guardgress/limit-period": "20-S",
	}
	ingressLimiter := GetIngressLimiter(ingressExactPathMock)

	t.Run("test 20-S Period", func(t *testing.T) {
		assert.Equal(t, int64(20), ingressLimiter.Rate.Limit)
		assert.Equal(t, time.Second, ingressLimiter.Rate.Period)
	})

	ingressExactPathMock = mocks.IngressExactPathTypeMock()
	ingressExactPathMock.Annotations = map[string]string{
		"guardgress/limit-period": "20-H",
	}
	ingressLimiter = GetIngressLimiter(ingressExactPathMock)

	t.Run("test 20H Period", func(t *testing.T) {
		assert.Equal(t, int64(20), ingressLimiter.Rate.Limit)
		assert.Equal(t, time.Hour, ingressLimiter.Rate.Period)
	})

	t.Run("test no limit period", func(t *testing.T) {
		ingressExactPathMock = mocks.IngressExactPathTypeMock()
		ingressExactPathMock.Annotations = map[string]string{}
		ingressLimiter = GetIngressLimiter(ingressExactPathMock)
		assert.Nil(t, ingressLimiter)
	})
}

func TestRateLimitTriggeredRPS1(t *testing.T) {
	mockIp := "127.0.0.1"
	ingressExactPathMock := mocks.IngressExactPathTypeMock()
	ingressExactPathMock.Annotations = map[string]string{
		"guardgress/limit-period": "1-S",
	}

	t.Run("test 1 request in 1S Period", func(t *testing.T) {
		ingressLimiter := GetIngressLimiter(ingressExactPathMock)
		assert.False(t, IsLimited(ingressLimiter, ingressExactPathMock.Annotations, mockIp, ""))
		assert.True(t, IsLimited(ingressLimiter, ingressExactPathMock.Annotations, mockIp, ""))
		assert.True(t, IsLimited(ingressLimiter, ingressExactPathMock.Annotations, mockIp, ""))
		time.Sleep(time.Second * 1)
		assert.False(t, IsLimited(ingressLimiter, ingressExactPathMock.Annotations, mockIp, ""))
		assert.True(t, IsLimited(ingressLimiter, ingressExactPathMock.Annotations, mockIp, ""))
		time.Sleep(time.Millisecond * 500)
		assert.True(t, IsLimited(ingressLimiter, ingressExactPathMock.Annotations, mockIp, ""))
		time.Sleep(time.Millisecond * 500)
		assert.False(t, IsLimited(ingressLimiter, ingressExactPathMock.Annotations, mockIp, ""))
	})
}

func TestRateLimitTriggeredRPS10(t *testing.T) {
	mockIp := "127.0.0.1"

	// Mocking ingress with the desired limit period
	ingressExactPathMock := mocks.IngressExactPathTypeMock()
	ingressExactPathMock.Annotations = map[string]string{
		"guardgress/limit-period": "50-S",
	}
	ingressLimiter := GetIngressLimiter(ingressExactPathMock)

	t.Run("test 51 requests in 50S Period", func(t *testing.T) {
		const numRequests = 50
		var wg sync.WaitGroup
		wg.Add(numRequests)

		// Simulating multiple requests concurrently
		for i := 0; i < numRequests; i++ {
			go func(wg *sync.WaitGroup) {
				defer wg.Done()
				log.Info("simulating request")
				assert.False(t, IsLimited(ingressLimiter, ingressExactPathMock.Annotations, mockIp, ""))
			}(&wg)
		}
		wg.Wait()

		// The IP should be limited after reaching the specified limit
		assert.True(t, IsLimited(ingressLimiter, ingressExactPathMock.Annotations, mockIp, ""))
	})
}

func TestRateLimitTriggeredRPM10(t *testing.T) {
	mockIp := "127.0.0.1"
	ingressExactPathMock := mocks.IngressExactPathTypeMock()
	ingressExactPathMock.Annotations = map[string]string{
		"guardgress/limit-period": "5-M",
	}
	ingressLimiter := GetIngressLimiter(ingressExactPathMock)

	t.Run("test 10 requests in 5M Period", func(t *testing.T) {
		for i := 1; i <= 10; i++ {
			if i <= 5 {
				assert.False(t, IsLimited(ingressLimiter, ingressExactPathMock.Annotations, mockIp, ""))
			} else {
				assert.True(t, IsLimited(ingressLimiter, ingressExactPathMock.Annotations, mockIp, ""))
			}
		}
	})

}

func TestCreatingRedisClient(t *testing.T) {
	t.Run("test redis url does not start with redis://", func(t *testing.T) {
		redisUrl := "foo://localhost:6379"
		client, err := GetRedisClient(redisUrl)
		assert.Error(t, err)
		assert.Nil(t, client)
	})

	t.Run("test redis url does start with redis://", func(t *testing.T) {
		redisUrl := "redis://localhost:6379"
		assert.True(t, strings.HasPrefix(redisUrl, "redis://"))
	})
}

func TestRateLimitNotTriggeredOnWhitelistedPath(t *testing.T) {
	mockIp := "127.0.0.1"
	ingressExactPathMock := mocks.IngressExactPathTypeMock()
	ingressExactPathMock.Annotations = map[string]string{
		"guardgress/limit-period":         "1-S",
		"guardgress/limit-path-whitelist": "/foo,/.well-known",
	}
	ingressLimiter := GetIngressLimiter(ingressExactPathMock)

	t.Run("test be whitelisted /.well-known", func(t *testing.T) {
		for i := 1; i <= 10; i++ {
			assert.False(t, IsLimited(ingressLimiter, ingressExactPathMock.Annotations, mockIp, "/.well-known"))
		}
	})

	t.Run("test be whitelisted /foo", func(t *testing.T) {
		for i := 1; i <= 10; i++ {
			assert.False(t, IsLimited(ingressLimiter, ingressExactPathMock.Annotations, mockIp, "/foo"))
		}
	})

	ingressExactPathMock.Annotations = map[string]string{
		"guardgress/limit-period":         "1-M",
		"guardgress/limit-path-whitelist": "/.well-known",
	}

	// test only /.well-known
	t.Run("test only /.well-known", func(t *testing.T) {
		for i := 1; i <= 10; i++ {
			assert.False(t, IsLimited(ingressLimiter, ingressExactPathMock.Annotations, mockIp, "/.well-known"))
		}
	})

	t.Run("test be not whitelisted /should-be-limited", func(t *testing.T) {
		for i := 1; i <= 10; i++ {
			isLimited := IsLimited(ingressLimiter, ingressExactPathMock.Annotations, mockIp, "/should-be-limited")
			if i > 5 {
				assert.True(t, isLimited)
			}
		}
	})

}
