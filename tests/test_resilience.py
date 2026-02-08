"""
Tests for Resilience Utilities.

Covers:
- Retry logic with different strategies
- Circuit breaker state transitions
- Graceful degradation and fallbacks
- Health checking system
- Timeout handling
- Rate limiting
- Bulkhead pattern
"""

import pytest
import time
import asyncio
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock

from utils.resilience import (
    # Retry
    RetryStrategy,
    RetryConfig,
    RetryResult,
    retry,
    async_retry,
    retry_async_operation,
    # Circuit Breaker
    CircuitState,
    CircuitBreakerConfig,
    CircuitBreaker,
    CircuitBreakerError,
    CircuitBreakerRegistry,
    circuit_registry,
    # Graceful Degradation
    DegradedResponse,
    FallbackConfig,
    FallbackCache,
    with_fallback,
    GracefulDegradation,
    # Health Checking
    HealthStatus,
    HealthCheckResult,
    HealthChecker,
    # Timeout
    TimeoutError,
    with_timeout,
    timeout,
    # Rate Limiting
    RateLimitExceeded,
    RateLimitConfig,
    RateLimiter,
    rate_limit,
    # Bulkhead
    BulkheadFull,
    Bulkhead,
)


# ============================================================================
# Retry Configuration Tests
# ============================================================================

class TestRetryConfig:
    """Test retry configuration and delay calculation."""
    
    def test_fixed_delay_strategy(self):
        """Fixed strategy should return constant delay."""
        config = RetryConfig(
            base_delay=2.0,
            strategy=RetryStrategy.FIXED,
            jitter=False
        )
        
        assert config.get_delay(0) == 2.0
        assert config.get_delay(1) == 2.0
        assert config.get_delay(5) == 2.0
    
    def test_exponential_delay_strategy(self):
        """Exponential strategy should double delay each attempt."""
        config = RetryConfig(
            base_delay=1.0,
            max_delay=100.0,
            strategy=RetryStrategy.EXPONENTIAL,
            jitter=False
        )
        
        assert config.get_delay(0) == 1.0   # 1 * 2^0
        assert config.get_delay(1) == 2.0   # 1 * 2^1
        assert config.get_delay(2) == 4.0   # 1 * 2^2
        assert config.get_delay(3) == 8.0   # 1 * 2^3
    
    def test_linear_delay_strategy(self):
        """Linear strategy should increase linearly."""
        config = RetryConfig(
            base_delay=1.0,
            strategy=RetryStrategy.LINEAR,
            jitter=False
        )
        
        assert config.get_delay(0) == 1.0
        assert config.get_delay(1) == 2.0
        assert config.get_delay(2) == 3.0
    
    def test_fibonacci_delay_strategy(self):
        """Fibonacci strategy should follow Fibonacci sequence."""
        config = RetryConfig(
            base_delay=1.0,
            strategy=RetryStrategy.FIBONACCI,
            jitter=False
        )
        
        # Fibonacci: 0, 1, 1, 2, 3, 5, 8, 13...
        assert config.get_delay(0) == 1.0   # fib(1) = 1
        assert config.get_delay(1) == 1.0   # fib(2) = 1
        assert config.get_delay(2) == 2.0   # fib(3) = 2
        assert config.get_delay(3) == 3.0   # fib(4) = 3
        assert config.get_delay(4) == 5.0   # fib(5) = 5
    
    def test_max_delay_cap(self):
        """Delay should be capped at max_delay."""
        config = RetryConfig(
            base_delay=10.0,
            max_delay=20.0,
            strategy=RetryStrategy.EXPONENTIAL,
            jitter=False
        )
        
        assert config.get_delay(0) == 10.0
        assert config.get_delay(1) == 20.0  # Would be 20, capped at 20
        assert config.get_delay(5) == 20.0  # Would be 320, capped at 20
    
    def test_jitter_adds_randomness(self):
        """Jitter should add randomness to delay."""
        config = RetryConfig(
            base_delay=10.0,
            strategy=RetryStrategy.FIXED,
            jitter=True,
            jitter_factor=0.2
        )
        
        # Get multiple delays and ensure they're not all the same
        delays = [config.get_delay(0) for _ in range(10)]
        unique_delays = len(set(delays))
        
        # With jitter, we should get varying delays
        assert unique_delays > 1
        # All delays should be within jitter range (10 ± 2)
        assert all(8.0 <= d <= 12.0 for d in delays)


# ============================================================================
# Retry Decorator Tests
# ============================================================================

class TestRetryDecorator:
    """Test retry decorator functionality."""
    
    def test_succeeds_on_first_try(self):
        """Should return immediately on success."""
        call_count = 0
        
        @retry(RetryConfig(max_attempts=3))
        def successful_func():
            nonlocal call_count
            call_count += 1
            return "success"
        
        result = successful_func()
        assert result == "success"
        assert call_count == 1
    
    def test_retries_on_failure(self):
        """Should retry on retryable exceptions."""
        call_count = 0
        
        @retry(RetryConfig(max_attempts=3, base_delay=0.01))
        def flaky_func():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("Not yet")
            return "success"
        
        result = flaky_func()
        assert result == "success"
        assert call_count == 3
    
    def test_raises_after_max_attempts(self):
        """Should raise after exhausting attempts."""
        @retry(RetryConfig(max_attempts=3, base_delay=0.01))
        def always_fails():
            raise ValueError("Always fails")
        
        with pytest.raises(ValueError, match="Always fails"):
            always_fails()
    
    def test_respects_non_retryable_exceptions(self):
        """Should not retry non-retryable exceptions."""
        call_count = 0
        
        @retry(RetryConfig(
            max_attempts=5,
            base_delay=0.01,
            non_retryable_exceptions=(KeyError,)
        ))
        def func_with_keyerror():
            nonlocal call_count
            call_count += 1
            raise KeyError("Not retryable")
        
        with pytest.raises(KeyError):
            func_with_keyerror()
        
        assert call_count == 1  # Should not retry
    
    def test_only_retries_specified_exceptions(self):
        """Should only retry specified exception types."""
        call_count = 0
        
        @retry(RetryConfig(
            max_attempts=5,
            base_delay=0.01,
            retryable_exceptions=(ConnectionError,)
        ))
        def func_with_valueerror():
            nonlocal call_count
            call_count += 1
            raise ValueError("Not retryable")
        
        with pytest.raises(ValueError):
            func_with_valueerror()
        
        assert call_count == 1


# ============================================================================
# Async Retry Tests
# ============================================================================

class TestAsyncRetry:
    """Test async retry functionality."""
    
    @pytest.mark.asyncio
    async def test_async_retry_succeeds(self):
        """Async retry should work on success."""
        call_count = 0
        
        @async_retry(RetryConfig(max_attempts=3))
        async def async_func():
            nonlocal call_count
            call_count += 1
            return "success"
        
        result = await async_func()
        assert result == "success"
        assert call_count == 1
    
    @pytest.mark.asyncio
    async def test_async_retry_operation(self):
        """retry_async_operation should work."""
        call_count = 0
        
        async def flaky_async():
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise ConnectionError("Retry me")
            return "success"
        
        result = await retry_async_operation(
            flaky_async,
            RetryConfig(max_attempts=3, base_delay=0.01)
        )
        assert result == "success"
        assert call_count == 2


# ============================================================================
# Circuit Breaker Tests
# ============================================================================

class TestCircuitBreaker:
    """Test circuit breaker state machine."""
    
    def test_starts_closed(self):
        """Circuit should start in closed state."""
        cb = CircuitBreaker("test")
        assert cb.is_closed
        assert cb.state == CircuitState.CLOSED
    
    def test_opens_after_threshold_failures(self):
        """Circuit should open after failure threshold."""
        cb = CircuitBreaker("test", CircuitBreakerConfig(failure_threshold=3))
        
        def failing_func():
            raise ValueError("Failure")
        
        for _ in range(3):
            with pytest.raises(ValueError):
                cb.call(failing_func)
        
        assert cb.is_open
        assert cb.state == CircuitState.OPEN
    
    def test_rejects_calls_when_open(self):
        """Open circuit should reject calls."""
        cb = CircuitBreaker("test", CircuitBreakerConfig(failure_threshold=1))
        
        # Trip the circuit
        with pytest.raises(ZeroDivisionError):
            cb.call(lambda: 1/0)
        
        # Should be open now
        # Next call should be rejected
        with pytest.raises(CircuitBreakerError, match="is OPEN"):
            cb.call(lambda: "success")
    
    def test_half_open_after_timeout(self):
        """Circuit should go half-open after timeout."""
        cb = CircuitBreaker("test", CircuitBreakerConfig(
            failure_threshold=1,
            timeout=0.1
        ))
        
        # Trip the circuit
        with pytest.raises(Exception):
            cb.call(lambda: 1/0)
        
        assert cb.is_open
        
        # Wait for timeout
        time.sleep(0.15)
        
        # Should allow calls (triggers half-open)
        assert cb.can_execute()
        assert cb.is_half_open
    
    def test_closes_after_success_threshold(self):
        """Circuit should close after success threshold in half-open."""
        cb = CircuitBreaker("test", CircuitBreakerConfig(
            failure_threshold=1,
            success_threshold=2,
            timeout=0.01
        ))
        
        # Trip it
        with pytest.raises(Exception):
            cb.call(lambda: 1/0)
        
        time.sleep(0.02)  # Wait for timeout
        
        # Successful calls in half-open
        cb.call(lambda: "success")
        cb.call(lambda: "success")
        
        assert cb.is_closed
    
    def test_reopens_on_failure_in_half_open(self):
        """Circuit should reopen on failure in half-open."""
        cb = CircuitBreaker("test", CircuitBreakerConfig(
            failure_threshold=1,
            timeout=0.01
        ))
        
        # Trip it
        with pytest.raises(Exception):
            cb.call(lambda: 1/0)
        
        time.sleep(0.02)  # Wait for timeout
        
        # Fail in half-open
        with pytest.raises(Exception):
            cb.call(lambda: 1/0)
        
        assert cb.is_open
    
    def test_as_decorator(self):
        """Circuit breaker should work as decorator."""
        cb = CircuitBreaker("test")
        
        @cb
        def protected_func():
            return "success"
        
        result = protected_func()
        assert result == "success"
    
    def test_reset(self):
        """Manual reset should close circuit."""
        cb = CircuitBreaker("test", CircuitBreakerConfig(failure_threshold=1))
        
        # Trip it
        with pytest.raises(Exception):
            cb.call(lambda: 1/0)
        
        assert cb.is_open
        
        cb.reset()
        assert cb.is_closed
    
    def test_get_status(self):
        """Should return status dict."""
        cb = CircuitBreaker("test")
        status = cb.get_status()
        
        assert status["name"] == "test"
        assert status["state"] == "closed"
        assert "failure_count" in status


# ============================================================================
# Circuit Breaker Registry Tests
# ============================================================================

class TestCircuitBreakerRegistry:
    """Test circuit breaker registry."""
    
    def test_get_or_create(self):
        """Registry should get or create breakers."""
        registry = CircuitBreakerRegistry()
        
        cb1 = registry.get("test")
        cb2 = registry.get("test")
        
        assert cb1 is cb2
    
    def test_reset_all(self):
        """Should reset all breakers."""
        registry = CircuitBreakerRegistry()
        
        cb1 = registry.get("test1", CircuitBreakerConfig(failure_threshold=1))
        cb2 = registry.get("test2", CircuitBreakerConfig(failure_threshold=1))
        
        # Trip both
        with pytest.raises(Exception):
            cb1.call(lambda: 1/0)
        with pytest.raises(Exception):
            cb2.call(lambda: 1/0)
        
        registry.reset_all()
        
        assert cb1.is_closed
        assert cb2.is_closed


# ============================================================================
# Fallback Cache Tests
# ============================================================================

class TestFallbackCache:
    """Test fallback cache functionality."""
    
    def test_get_returns_none_for_missing(self):
        """Cache should return None for missing keys."""
        cache = FallbackCache()
        assert cache.get("missing") is None
    
    def test_set_and_get(self):
        """Should store and retrieve values."""
        cache = FallbackCache(FallbackConfig(cache_ttl=60.0))
        cache.set("key", "value")
        
        assert cache.get("key") == "value"
    
    def test_expired_returns_none(self):
        """Expired values should return None from get()."""
        cache = FallbackCache(FallbackConfig(cache_ttl=0.01))
        cache.set("key", "value")
        
        time.sleep(0.02)
        assert cache.get("key") is None
    
    def test_get_stale_returns_expired(self):
        """get_stale should return expired values within stale_ttl."""
        cache = FallbackCache(FallbackConfig(
            cache_ttl=0.01,
            stale_ttl=1.0
        ))
        cache.set("key", "value")
        
        time.sleep(0.02)
        assert cache.get("key") is None
        assert cache.get_stale("key") == "value"
    
    def test_invalidate(self):
        """Should remove key from cache."""
        cache = FallbackCache()
        cache.set("key", "value")
        cache.invalidate("key")
        
        assert cache.get("key") is None
    
    def test_clear(self):
        """Should clear all cache."""
        cache = FallbackCache()
        cache.set("key1", "value1")
        cache.set("key2", "value2")
        cache.clear()
        
        assert cache.get("key1") is None
        assert cache.get("key2") is None


# ============================================================================
# Graceful Degradation Tests
# ============================================================================

class TestGracefulDegradation:
    """Test graceful degradation strategies."""
    
    def test_returns_primary_on_success(self):
        """Should return primary result on success."""
        gd = GracefulDegradation()
        gd.register_strategy("test", [lambda: "fallback1"])
        
        result = gd.execute("test", lambda: "primary")
        assert result == "primary"
    
    def test_uses_fallback_on_failure(self):
        """Should use fallback when primary fails."""
        gd = GracefulDegradation()
        gd.register_strategy("test", [lambda: "fallback1"])
        
        def failing_primary():
            raise ValueError("Primary failed")
        
        result = gd.execute("test", failing_primary)
        assert result == "fallback1"
    
    def test_tries_fallbacks_in_order(self):
        """Should try fallbacks in order."""
        gd = GracefulDegradation()
        
        call_order = []
        
        def fallback1():
            call_order.append("f1")
            raise ValueError("Fallback 1 failed")
        
        def fallback2():
            call_order.append("f2")
            return "fallback2_result"
        
        gd.register_strategy("test", [fallback1, fallback2])
        
        result = gd.execute("test", lambda: 1/0)
        
        assert result == "fallback2_result"
        assert call_order == ["f1", "f2"]
    
    def test_raises_when_all_fail(self):
        """Should raise when all strategies fail."""
        gd = GracefulDegradation()
        gd.register_strategy("test", [
            lambda: 1/0,
            lambda: 1/0
        ])
        
        with pytest.raises(RuntimeError, match="All strategies exhausted"):
            gd.execute("test", lambda: 1/0)
    
    def test_uses_cached_value(self):
        """Should use cached value when available."""
        gd = GracefulDegradation()
        gd.register_strategy(
            "test", 
            [],
            cache_config=FallbackConfig(cache_ttl=60.0, stale_ttl=120.0)
        )
        
        # First call succeeds and caches
        result1 = gd.execute("test", lambda: "cached_value")
        assert result1 == "cached_value"
        
        # Second call fails but uses cache
        result2 = gd.execute("test", lambda: 1/0)
        assert result2 == "cached_value"
    
    def test_tracks_metrics(self):
        """Should track execution metrics."""
        gd = GracefulDegradation()
        gd.register_strategy("test", [lambda: "fallback"])
        
        gd.execute("test", lambda: "primary")
        gd.execute("test", lambda: 1/0)  # Uses fallback
        
        metrics = gd.get_metrics("test")
        assert metrics["primary_calls"] == 1
        assert metrics["fallback_calls"] == 1


# ============================================================================
# Health Checker Tests
# ============================================================================

class TestHealthChecker:
    """Test health checking system."""
    
    def test_register_and_run_check(self):
        """Should register and run health checks."""
        hc = HealthChecker()
        hc.register_check("test", lambda: True)
        
        result = hc.run_check("test")
        assert result.status == HealthStatus.HEALTHY
    
    def test_unhealthy_on_failure(self):
        """Should report unhealthy on check failure."""
        hc = HealthChecker()
        hc.register_check("test", lambda: 1/0)
        
        result = hc.run_check("test")
        assert result.status == HealthStatus.UNHEALTHY
    
    def test_returns_check_result_directly(self):
        """Should pass through HealthCheckResult objects."""
        hc = HealthChecker()
        
        def custom_check():
            return HealthCheckResult(
                name="custom",
                status=HealthStatus.DEGRADED,
                message="Custom message"
            )
        
        hc.register_check("test", custom_check)
        result = hc.run_check("test")
        
        assert result.status == HealthStatus.DEGRADED
        assert result.message == "Custom message"
    
    def test_overall_healthy(self):
        """Overall status should be healthy when all checks pass."""
        hc = HealthChecker()
        hc.register_check("check1", lambda: True)
        hc.register_check("check2", lambda: True)
        
        hc.run_all_checks()
        assert hc.get_overall_status() == HealthStatus.HEALTHY
    
    def test_overall_unhealthy(self):
        """Overall status should be unhealthy when any check fails."""
        hc = HealthChecker()
        hc.register_check("check1", lambda: True)
        hc.register_check("check2", lambda: 1/0)
        
        hc.run_all_checks()
        assert hc.get_overall_status() == HealthStatus.UNHEALTHY
    
    def test_tracks_latency(self):
        """Should track check latency."""
        hc = HealthChecker()
        
        def slow_check():
            time.sleep(0.1)
            return True
        
        hc.register_check("slow", slow_check)
        result = hc.run_check("slow")
        
        assert result.latency_ms >= 100
    
    def test_get_health_report(self):
        """Should generate comprehensive health report."""
        hc = HealthChecker("test-service")
        hc.register_check("db", lambda: True)
        hc.register_check("cache", lambda: True)
        
        report = hc.get_health_report()
        
        assert report["service"] == "test-service"
        assert report["status"] == "healthy"
        assert "db" in report["checks"]
        assert "cache" in report["checks"]
    
    def test_maintains_history(self):
        """Should maintain check history."""
        hc = HealthChecker()
        hc.register_check("test", lambda: True)
        
        for _ in range(5):
            hc.run_check("test")
        
        history = hc.get_check_history("test")
        assert len(history) == 5


# ============================================================================
# Rate Limiter Tests
# ============================================================================

class TestRateLimiter:
    """Test rate limiting functionality."""
    
    def test_allows_within_limit(self):
        """Should allow requests within limit."""
        limiter = RateLimiter(rate=10, burst=5)
        
        # Should allow burst
        for _ in range(5):
            assert limiter.acquire() is True
    
    def test_rejects_over_limit(self):
        """Should reject requests over limit."""
        limiter = RateLimiter(rate=1, burst=2)
        
        # Use up burst
        limiter.acquire()
        limiter.acquire()
        
        # Should reject
        assert limiter.acquire() is False
    
    def test_refills_over_time(self):
        """Should refill tokens over time."""
        limiter = RateLimiter(rate=100, burst=2)  # 100 tokens/sec
        
        # Use up burst
        limiter.acquire()
        limiter.acquire()
        
        # Wait for refill
        time.sleep(0.05)  # Should refill ~5 tokens
        
        assert limiter.acquire() is True
    
    def test_wait_blocks_until_available(self):
        """wait() should block until tokens available."""
        limiter = RateLimiter(rate=100, burst=1)
        
        limiter.acquire()  # Use up burst
        
        start = time.time()
        wait_time = limiter.wait()
        elapsed = time.time() - start
        
        assert wait_time > 0
        assert elapsed >= wait_time * 0.9  # Allow some tolerance
    
    def test_as_decorator(self):
        """Should work as decorator."""
        limiter = RateLimiter(rate=1000, burst=10)
        
        @limiter
        def limited_func():
            return "result"
        
        result = limited_func()
        assert result == "result"
    
    def test_rate_limit_decorator_factory(self):
        """rate_limit decorator factory should work."""
        @rate_limit(rate=100, burst=5)
        def limited_func():
            return "result"
        
        result = limited_func()
        assert result == "result"


# ============================================================================
# Timeout Tests
# ============================================================================

class TestTimeout:
    """Test timeout functionality."""
    
    def test_completes_within_timeout(self):
        """Should complete if within timeout."""
        @with_timeout(1.0)
        def fast_func():
            return "fast"
        
        result = fast_func()
        assert result == "fast"
    
    def test_raises_on_timeout(self):
        """Should raise TimeoutError if exceeds timeout."""
        @with_timeout(0.1)
        def slow_func():
            time.sleep(0.5)
            return "slow"
        
        with pytest.raises(TimeoutError, match="timed out"):
            slow_func()
    
    def test_timeout_alias(self):
        """timeout alias should work."""
        @timeout(1.0)
        def fast_func():
            return "fast"
        
        result = fast_func()
        assert result == "fast"


# ============================================================================
# Bulkhead Tests
# ============================================================================

class TestBulkhead:
    """Test bulkhead pattern."""
    
    def test_allows_within_capacity(self):
        """Should allow calls within capacity."""
        bulkhead = Bulkhead("test", max_concurrent=2)
        
        @bulkhead
        def simple_func():
            return "result"
        
        result = simple_func()
        assert result == "result"
    
    def test_get_status(self):
        """Should return status."""
        bulkhead = Bulkhead("test", max_concurrent=5, max_waiting=10)
        status = bulkhead.get_status()
        
        assert status["name"] == "test"
        assert status["max_concurrent"] == 5
        assert status["max_waiting"] == 10


# ============================================================================
# Integration Tests
# ============================================================================

class TestResilienceIntegration:
    """Integration tests for combined resilience patterns."""
    
    def test_retry_with_circuit_breaker(self):
        """Test retry inside circuit breaker."""
        cb = CircuitBreaker("test", CircuitBreakerConfig(failure_threshold=10))
        call_count = 0
        
        @cb
        @retry(RetryConfig(max_attempts=3, base_delay=0.01))
        def flaky_service():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ConnectionError("Service unavailable")
            return "success"
        
        result = flaky_service()
        assert result == "success"
        assert call_count == 3
        assert cb.is_closed  # Circuit should still be closed
    
    def test_fallback_with_health_check(self):
        """Test graceful degradation with health monitoring."""
        hc = HealthChecker()
        gd = GracefulDegradation()
        
        service_healthy = True
        
        def check_service():
            return service_healthy
        
        hc.register_check("service", check_service)
        gd.register_strategy("data", [lambda: "fallback_data"])
        
        def get_data():
            if not service_healthy:
                raise ConnectionError("Service down")
            return "primary_data"
        
        # Service healthy
        result1 = gd.execute("data", get_data)
        assert result1 == "primary_data"
        
        # Service unhealthy
        service_healthy = False
        result2 = gd.execute("data", get_data)
        assert result2 == "fallback_data"
        
        # Health check reflects status
        hc.run_all_checks()
        assert hc.get_overall_status() == HealthStatus.UNHEALTHY
