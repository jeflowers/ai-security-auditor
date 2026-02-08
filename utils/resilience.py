"""
Resilience Utilities for AI Security Auditor.

Provides production-grade reliability patterns:
- Retry logic with exponential backoff
- Circuit breakers for external services
- Graceful degradation strategies
- Health checking and monitoring
"""

import asyncio
import functools
import logging
import random
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable, Optional, TypeVar, Generic
from collections import deque

logger = logging.getLogger(__name__)

T = TypeVar('T')


# ============================================================================
# Retry Logic
# ============================================================================

class RetryStrategy(Enum):
    """Retry timing strategies."""
    FIXED = "fixed"
    EXPONENTIAL = "exponential"
    LINEAR = "linear"
    FIBONACCI = "fibonacci"


@dataclass
class RetryConfig:
    """Configuration for retry behavior."""
    max_attempts: int = 3
    base_delay: float = 1.0  # seconds
    max_delay: float = 60.0  # seconds
    strategy: RetryStrategy = RetryStrategy.EXPONENTIAL
    jitter: bool = True
    jitter_factor: float = 0.1
    retryable_exceptions: tuple = (Exception,)
    non_retryable_exceptions: tuple = ()
    
    def get_delay(self, attempt: int) -> float:
        """Calculate delay for given attempt number."""
        if self.strategy == RetryStrategy.FIXED:
            delay = self.base_delay
        elif self.strategy == RetryStrategy.EXPONENTIAL:
            delay = self.base_delay * (2 ** attempt)
        elif self.strategy == RetryStrategy.LINEAR:
            delay = self.base_delay * (attempt + 1)
        elif self.strategy == RetryStrategy.FIBONACCI:
            delay = self.base_delay * self._fibonacci(attempt + 1)
        else:
            delay = self.base_delay
        
        # Apply max delay cap
        delay = min(delay, self.max_delay)
        
        # Apply jitter if enabled
        if self.jitter:
            jitter_range = delay * self.jitter_factor
            delay += random.uniform(-jitter_range, jitter_range)
        
        return max(0, delay)
    
    @staticmethod
    def _fibonacci(n: int) -> int:
        """Calculate nth Fibonacci number."""
        if n <= 1:
            return n
        a, b = 0, 1
        for _ in range(n - 1):
            a, b = b, a + b
        return b


@dataclass
class RetryResult(Generic[T]):
    """Result of a retry operation."""
    success: bool
    value: Optional[T] = None
    attempts: int = 0
    total_delay: float = 0.0
    last_exception: Optional[Exception] = None
    exceptions: list = field(default_factory=list)


def retry(config: Optional[RetryConfig] = None):
    """
    Decorator for adding retry logic to functions.
    
    Usage:
        @retry(RetryConfig(max_attempts=5))
        def flaky_operation():
            ...
    """
    if config is None:
        config = RetryConfig()
    
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            result = RetryResult(success=False)
            
            for attempt in range(config.max_attempts):
                result.attempts = attempt + 1
                
                try:
                    value = func(*args, **kwargs)
                    result.success = True
                    result.value = value
                    return value
                    
                except config.non_retryable_exceptions as e:
                    # Don't retry these
                    result.last_exception = e
                    result.exceptions.append(e)
                    raise
                    
                except config.retryable_exceptions as e:
                    result.last_exception = e
                    result.exceptions.append(e)
                    
                    if attempt < config.max_attempts - 1:
                        delay = config.get_delay(attempt)
                        result.total_delay += delay
                        logger.warning(
                            f"Retry {attempt + 1}/{config.max_attempts} for {func.__name__} "
                            f"after {delay:.2f}s. Error: {e}"
                        )
                        time.sleep(delay)
                    else:
                        logger.error(
                            f"All {config.max_attempts} attempts failed for {func.__name__}"
                        )
                        raise
            
            return result
        
        return wrapper
    return decorator


def async_retry(config: Optional[RetryConfig] = None):
    """Async version of retry decorator."""
    if config is None:
        config = RetryConfig()
    
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs) -> Any:
            result = RetryResult(success=False)
            
            for attempt in range(config.max_attempts):
                result.attempts = attempt + 1
                
                try:
                    value = await func(*args, **kwargs)
                    result.success = True
                    result.value = value
                    return value
                    
                except config.non_retryable_exceptions as e:
                    result.last_exception = e
                    result.exceptions.append(e)
                    raise
                    
                except config.retryable_exceptions as e:
                    result.last_exception = e
                    result.exceptions.append(e)
                    
                    if attempt < config.max_attempts - 1:
                        delay = config.get_delay(attempt)
                        result.total_delay += delay
                        logger.warning(
                            f"Async retry {attempt + 1}/{config.max_attempts} for "
                            f"{func.__name__} after {delay:.2f}s. Error: {e}"
                        )
                        await asyncio.sleep(delay)
                    else:
                        logger.error(
                            f"All {config.max_attempts} async attempts failed for "
                            f"{func.__name__}"
                        )
                        raise
            
            return result
        
        return wrapper
    return decorator


# Alias for backward compatibility
retry_async = async_retry


async def retry_async_operation(
    operation: Callable,
    config: Optional[RetryConfig] = None,
    *args,
    **kwargs
) -> Any:
    """
    Execute an async operation with retry logic.
    
    Usage:
        result = await retry_async_operation(my_async_func, RetryConfig(), arg1, arg2)
    """
    if config is None:
        config = RetryConfig()
    
    for attempt in range(config.max_attempts):
        try:
            if asyncio.iscoroutinefunction(operation):
                return await operation(*args, **kwargs)
            else:
                return operation(*args, **kwargs)
        except config.non_retryable_exceptions:
            raise
        except config.retryable_exceptions as e:
            if attempt < config.max_attempts - 1:
                delay = config.get_delay(attempt)
                logger.warning(f"Retry {attempt + 1}/{config.max_attempts}: {e}")
                await asyncio.sleep(delay)
            else:
                raise


# ============================================================================
# Circuit Breaker
# ============================================================================

class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing, reject requests
    HALF_OPEN = "half_open"  # Testing if service recovered


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker."""
    failure_threshold: int = 5
    success_threshold: int = 2
    timeout: float = 30.0  # seconds before half-open
    half_open_max_calls: int = 3
    excluded_exceptions: tuple = ()


class CircuitBreakerError(Exception):
    """Raised when circuit is open."""
    pass


class CircuitBreaker:
    """
    Circuit breaker implementation.
    
    Prevents cascading failures by stopping calls to failing services.
    """
    
    def __init__(self, name: str, config: Optional[CircuitBreakerConfig] = None):
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time: Optional[datetime] = None
        self.half_open_calls = 0
    
    @property
    def is_closed(self) -> bool:
        return self.state == CircuitState.CLOSED
    
    @property
    def is_open(self) -> bool:
        return self.state == CircuitState.OPEN
    
    @property
    def is_half_open(self) -> bool:
        return self.state == CircuitState.HALF_OPEN
    
    def _should_attempt_reset(self) -> bool:
        """Check if enough time has passed to try half-open."""
        if self.last_failure_time is None:
            return True
        
        elapsed = (datetime.now(timezone.utc) - self.last_failure_time).total_seconds()
        return elapsed >= self.config.timeout
    
    def _record_success(self) -> None:
        """Record a successful call."""
        self.failure_count = 0
        
        if self.state == CircuitState.HALF_OPEN:
            self.success_count += 1
            if self.success_count >= self.config.success_threshold:
                self._close()
    
    def _record_failure(self, exception: Exception) -> None:
        """Record a failed call."""
        if isinstance(exception, self.config.excluded_exceptions):
            return
        
        self.failure_count += 1
        self.last_failure_time = datetime.now(timezone.utc)
        self.success_count = 0
        
        if self.state == CircuitState.HALF_OPEN:
            self._open()
        elif self.failure_count >= self.config.failure_threshold:
            self._open()
    
    def _open(self) -> None:
        """Open the circuit."""
        self.state = CircuitState.OPEN
        logger.warning(f"Circuit breaker '{self.name}' OPENED")
    
    def _close(self) -> None:
        """Close the circuit."""
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.half_open_calls = 0
        logger.info(f"Circuit breaker '{self.name}' CLOSED")
    
    def _half_open(self) -> None:
        """Move to half-open state."""
        self.state = CircuitState.HALF_OPEN
        self.half_open_calls = 0
        logger.info(f"Circuit breaker '{self.name}' HALF-OPEN")
    
    def can_execute(self) -> bool:
        """Check if a call can be made."""
        if self.state == CircuitState.CLOSED:
            return True
        
        if self.state == CircuitState.OPEN:
            if self._should_attempt_reset():
                self._half_open()
                return True
            return False
        
        if self.state == CircuitState.HALF_OPEN:
            return self.half_open_calls < self.config.half_open_max_calls
        
        return False
    
    def __call__(self, func: Callable) -> Callable:
        """Use as decorator."""
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if not self.can_execute():
                raise CircuitBreakerError(
                    f"Circuit breaker '{self.name}' is OPEN"
                )
            
            if self.state == CircuitState.HALF_OPEN:
                self.half_open_calls += 1
            
            try:
                result = func(*args, **kwargs)
                self._record_success()
                return result
            except Exception as e:
                self._record_failure(e)
                raise
        
        return wrapper
    
    def call(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with circuit breaker protection."""
        if not self.can_execute():
            raise CircuitBreakerError(
                f"Circuit breaker '{self.name}' is OPEN"
            )
        
        if self.state == CircuitState.HALF_OPEN:
            self.half_open_calls += 1
        
        try:
            result = func(*args, **kwargs)
            self._record_success()
            return result
        except Exception as e:
            self._record_failure(e)
            raise
    
    async def call_async(self, func: Callable, *args, **kwargs) -> Any:
        """Execute async function with circuit breaker protection."""
        if not self.can_execute():
            raise CircuitBreakerError(
                f"Circuit breaker '{self.name}' is OPEN"
            )
        
        if self.state == CircuitState.HALF_OPEN:
            self.half_open_calls += 1
        
        try:
            result = await func(*args, **kwargs)
            self._record_success()
            return result
        except Exception as e:
            self._record_failure(e)
            raise
    
    def reset(self) -> None:
        """Manually reset the circuit breaker."""
        self._close()
    
    def get_status(self) -> dict:
        """Get current circuit breaker status."""
        return {
            "name": self.name,
            "state": self.state.value,
            "failure_count": self.failure_count,
            "success_count": self.success_count,
            "last_failure_time": (
                self.last_failure_time.isoformat() 
                if self.last_failure_time else None
            ),
            "half_open_calls": self.half_open_calls
        }


class CircuitBreakerRegistry:
    """Registry for managing multiple circuit breakers."""
    
    def __init__(self):
        self._breakers: dict[str, CircuitBreaker] = {}
    
    def get(self, name: str, config: Optional[CircuitBreakerConfig] = None) -> CircuitBreaker:
        """Get or create a circuit breaker by name."""
        if name not in self._breakers:
            self._breakers[name] = CircuitBreaker(name, config)
        return self._breakers[name]
    
    def get_all(self) -> dict[str, CircuitBreaker]:
        """Get all registered circuit breakers."""
        return self._breakers.copy()
    
    def reset_all(self) -> None:
        """Reset all circuit breakers."""
        for breaker in self._breakers.values():
            breaker.reset()
    
    def get_status(self) -> dict[str, dict]:
        """Get status of all circuit breakers."""
        return {name: cb.get_status() for name, cb in self._breakers.items()}


# Global circuit breaker registry
circuit_registry = CircuitBreakerRegistry()


# ============================================================================
# Graceful Degradation
# ============================================================================

@dataclass
class DegradedResponse(Generic[T]):
    """Response indicating degraded service."""
    value: T
    is_degraded: bool = True
    degradation_reason: str = ""
    original_error: Optional[Exception] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class FallbackConfig:
    """Configuration for fallback behavior."""
    cache_ttl: float = 300.0  # 5 minutes
    stale_ttl: float = 3600.0  # 1 hour for stale cache
    default_value: Any = None
    log_fallback: bool = True


class FallbackCache(Generic[T]):
    """
    Cache with fallback support for graceful degradation.
    
    Returns cached values when primary source fails.
    """
    
    def __init__(self, config: Optional[FallbackConfig] = None):
        self.config = config or FallbackConfig()
        self._cache: dict[str, tuple[T, datetime]] = {}
    
    def get(self, key: str) -> Optional[T]:
        """Get value from cache if not expired."""
        if key not in self._cache:
            return None
        
        value, timestamp = self._cache[key]
        age = (datetime.now(timezone.utc) - timestamp).total_seconds()
        
        if age <= self.config.cache_ttl:
            return value
        
        return None
    
    def get_stale(self, key: str) -> Optional[T]:
        """Get value even if stale (for fallback)."""
        if key not in self._cache:
            return None
        
        value, timestamp = self._cache[key]
        age = (datetime.now(timezone.utc) - timestamp).total_seconds()
        
        if age <= self.config.stale_ttl:
            return value
        
        return None
    
    def set(self, key: str, value: T) -> None:
        """Set value in cache."""
        self._cache[key] = (value, datetime.now(timezone.utc))
    
    def invalidate(self, key: str) -> None:
        """Remove key from cache."""
        self._cache.pop(key, None)
    
    def clear(self) -> None:
        """Clear all cache."""
        self._cache.clear()


def with_fallback(
    fallback_value: Any = None,
    cache: Optional[FallbackCache] = None,
    cache_key: Optional[str] = None
):
    """
    Decorator for graceful degradation with fallback values.
    
    Usage:
        @with_fallback(fallback_value=[], cache=my_cache, cache_key="users")
        def get_users():
            ...
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            key = cache_key or func.__name__
            
            try:
                result = func(*args, **kwargs)
                
                # Update cache on success
                if cache is not None:
                    cache.set(key, result)
                
                return result
                
            except Exception as e:
                logger.warning(f"Function {func.__name__} failed: {e}, using fallback")
                
                # Try cache first
                if cache is not None:
                    cached = cache.get_stale(key)
                    if cached is not None:
                        logger.info(f"Using cached value for {func.__name__}")
                        return cached
                
                # Return default fallback
                return fallback_value
        
        return wrapper
    return decorator


class GracefulDegradation:
    """
    Manager for graceful degradation strategies.
    
    Provides multiple levels of fallback for different failure scenarios.
    """
    
    def __init__(self):
        self.strategies: dict[str, list[Callable]] = {}
        self.caches: dict[str, FallbackCache] = {}
        self.metrics: dict[str, dict] = {}
    
    def register_strategy(
        self, 
        name: str, 
        fallbacks: list[Callable],
        cache_config: Optional[FallbackConfig] = None
    ) -> None:
        """Register a degradation strategy with ordered fallbacks."""
        self.strategies[name] = fallbacks
        if cache_config:
            self.caches[name] = FallbackCache(cache_config)
        self.metrics[name] = {
            "primary_calls": 0,
            "fallback_calls": 0,
            "cache_hits": 0,
            "total_failures": 0
        }
    
    def execute(
        self, 
        name: str, 
        primary: Callable, 
        *args, 
        **kwargs
    ) -> Any:
        """Execute with graceful degradation."""
        if name not in self.strategies:
            raise ValueError(f"Strategy '{name}' not registered")
        
        metrics = self.metrics[name]
        cache = self.caches.get(name)
        cache_key = f"{name}:{hash(args)}"
        
        # Try primary
        try:
            result = primary(*args, **kwargs)
            metrics["primary_calls"] += 1
            
            if cache:
                cache.set(cache_key, result)
            
            return result
            
        except Exception as primary_error:
            logger.warning(f"Primary failed for {name}: {primary_error}")
        
        # Try cached value
        if cache:
            cached = cache.get_stale(cache_key)
            if cached is not None:
                metrics["cache_hits"] += 1
                logger.info(f"Using cached value for {name}")
                return cached
        
        # Try fallbacks in order
        for i, fallback in enumerate(self.strategies[name]):
            try:
                result = fallback(*args, **kwargs)
                metrics["fallback_calls"] += 1
                logger.info(f"Fallback {i + 1} succeeded for {name}")
                return result
            except Exception as e:
                logger.warning(f"Fallback {i + 1} failed for {name}: {e}")
        
        # All fallbacks failed
        metrics["total_failures"] += 1
        raise RuntimeError(f"All strategies exhausted for {name}")
    
    def get_metrics(self, name: Optional[str] = None) -> dict:
        """Get degradation metrics."""
        if name:
            return self.metrics.get(name, {})
        return self.metrics.copy()


# ============================================================================
# Health Checking
# ============================================================================

class HealthStatus(Enum):
    """Health check status."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class HealthCheckResult:
    """Result of a health check."""
    name: str
    status: HealthStatus
    message: str = ""
    latency_ms: float = 0.0
    checked_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    details: dict = field(default_factory=dict)


class HealthChecker:
    """
    Health checking system for monitoring service health.
    """
    
    def __init__(self, name: str = "ai-security-auditor"):
        self.name = name
        self.checks: dict[str, Callable] = {}
        self.results: dict[str, HealthCheckResult] = {}
        self.history: dict[str, deque] = {}
        self.history_size = 100
    
    def register_check(self, name: str, check_func: Callable) -> None:
        """Register a health check function."""
        self.checks[name] = check_func
        self.history[name] = deque(maxlen=self.history_size)
    
    def run_check(self, name: str) -> HealthCheckResult:
        """Run a single health check."""
        if name not in self.checks:
            return HealthCheckResult(
                name=name,
                status=HealthStatus.UNKNOWN,
                message=f"Check '{name}' not registered"
            )
        
        start_time = time.time()
        
        try:
            result = self.checks[name]()
            latency = (time.time() - start_time) * 1000
            
            if isinstance(result, HealthCheckResult):
                result.latency_ms = latency
                check_result = result
            elif isinstance(result, bool):
                check_result = HealthCheckResult(
                    name=name,
                    status=HealthStatus.HEALTHY if result else HealthStatus.UNHEALTHY,
                    latency_ms=latency
                )
            else:
                check_result = HealthCheckResult(
                    name=name,
                    status=HealthStatus.HEALTHY,
                    latency_ms=latency,
                    details={"result": result}
                )
                
        except Exception as e:
            latency = (time.time() - start_time) * 1000
            check_result = HealthCheckResult(
                name=name,
                status=HealthStatus.UNHEALTHY,
                message=str(e),
                latency_ms=latency
            )
        
        self.results[name] = check_result
        self.history[name].append(check_result)
        
        return check_result
    
    def run_all_checks(self) -> dict[str, HealthCheckResult]:
        """Run all registered health checks."""
        results = {}
        for name in self.checks:
            results[name] = self.run_check(name)
        return results
    
    def get_overall_status(self) -> HealthStatus:
        """Get overall health status."""
        if not self.results:
            return HealthStatus.UNKNOWN
        
        statuses = [r.status for r in self.results.values()]
        
        if all(s == HealthStatus.HEALTHY for s in statuses):
            return HealthStatus.HEALTHY
        
        if any(s == HealthStatus.UNHEALTHY for s in statuses):
            return HealthStatus.UNHEALTHY
        
        return HealthStatus.DEGRADED
    
    def get_health_report(self) -> dict:
        """Get comprehensive health report."""
        self.run_all_checks()
        
        return {
            "service": self.name,
            "status": self.get_overall_status().value,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "checks": {
                name: {
                    "status": result.status.value,
                    "message": result.message,
                    "latency_ms": result.latency_ms,
                    "checked_at": result.checked_at.isoformat(),
                    "details": result.details
                }
                for name, result in self.results.items()
            }
        }
    
    def get_check_history(self, name: str, limit: int = 10) -> list[dict]:
        """Get recent history for a check."""
        if name not in self.history:
            return []
        
        history = list(self.history[name])[-limit:]
        return [
            {
                "status": r.status.value,
                "latency_ms": r.latency_ms,
                "checked_at": r.checked_at.isoformat()
            }
            for r in history
        ]


# ============================================================================
# Timeout Utilities
# ============================================================================

class TimeoutError(Exception):
    """Raised when operation times out."""
    pass


def with_timeout(seconds: float):
    """
    Decorator to add timeout to synchronous functions.
    
    Note: This uses threading and may not work with all code.
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            import concurrent.futures
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(func, *args, **kwargs)
                try:
                    return future.result(timeout=seconds)
                except concurrent.futures.TimeoutError:
                    raise TimeoutError(
                        f"Function {func.__name__} timed out after {seconds}s"
                    )
        
        return wrapper
    return decorator


# Alias for backward compatibility
timeout = with_timeout


def with_timeout_async(seconds: float):
    """Decorator to add timeout to async functions."""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                return await asyncio.wait_for(
                    func(*args, **kwargs),
                    timeout=seconds
                )
            except asyncio.TimeoutError:
                raise TimeoutError(
                    f"Async function {func.__name__} timed out after {seconds}s"
                )
        
        return wrapper
    return decorator


# ============================================================================
# Rate Limiting
# ============================================================================

class RateLimitExceeded(Exception):
    """Raised when rate limit is exceeded."""
    pass


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting."""
    rate: float  # tokens per second
    burst: int = 10  # maximum burst size
    blocking: bool = False  # if True, wait; if False, raise exception


class RateLimiter:
    """
    Token bucket rate limiter.
    
    Prevents overwhelming external services with too many requests.
    """
    
    def __init__(
        self, 
        rate: float = None,  # tokens per second
        burst: int = 10,  # maximum burst size
        config: Optional[RateLimitConfig] = None
    ):
        if config:
            self.rate = config.rate
            self.burst = config.burst
            self.blocking = config.blocking
        else:
            self.rate = rate or 1.0
            self.burst = burst
            self.blocking = False
        
        self.tokens = self.burst
        self.last_update = time.time()
    
    def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = time.time()
        elapsed = now - self.last_update
        self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
        self.last_update = now
    
    def acquire(self, tokens: int = 1) -> bool:
        """Try to acquire tokens. Returns False if not available."""
        self._refill()
        
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        
        return False
    
    def wait(self, tokens: int = 1) -> float:
        """Wait until tokens are available. Returns wait time."""
        self._refill()
        
        if self.tokens >= tokens:
            self.tokens -= tokens
            return 0.0
        
        needed = tokens - self.tokens
        wait_time = needed / self.rate
        time.sleep(wait_time)
        
        self._refill()
        self.tokens -= tokens
        
        return wait_time
    
    async def wait_async(self, tokens: int = 1) -> float:
        """Async version of wait."""
        self._refill()
        
        if self.tokens >= tokens:
            self.tokens -= tokens
            return 0.0
        
        needed = tokens - self.tokens
        wait_time = needed / self.rate
        await asyncio.sleep(wait_time)
        
        self._refill()
        self.tokens -= tokens
        
        return wait_time
    
    def __call__(self, func: Callable) -> Callable:
        """Use as decorator."""
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if self.blocking:
                self.wait()
            elif not self.acquire():
                raise RateLimitExceeded(f"Rate limit exceeded for {func.__name__}")
            return func(*args, **kwargs)
        
        return wrapper


def rate_limit(rate: float, burst: int = 10, blocking: bool = False):
    """
    Decorator factory for rate limiting.
    
    Usage:
        @rate_limit(rate=10, burst=5)
        def my_function():
            ...
    """
    limiter = RateLimiter(rate=rate, burst=burst)
    limiter.blocking = blocking
    
    def decorator(func: Callable) -> Callable:
        return limiter(func)
    
    return decorator


# ============================================================================
# Bulkhead Pattern
# ============================================================================

class BulkheadFull(Exception):
    """Raised when bulkhead is at capacity."""
    pass


class Bulkhead:
    """
    Bulkhead pattern implementation.
    
    Isolates failures by limiting concurrent executions.
    """
    
    def __init__(self, name: str, max_concurrent: int = 10, max_waiting: int = 10):
        self.name = name
        self.max_concurrent = max_concurrent
        self.max_waiting = max_waiting
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._sync_semaphore = None  # Created lazily for sync code
        self._waiting = 0
        self._active = 0
    
    def _get_sync_semaphore(self):
        """Get or create threading semaphore for sync code."""
        if self._sync_semaphore is None:
            import threading
            self._sync_semaphore = threading.Semaphore(self.max_concurrent)
        return self._sync_semaphore
    
    def __call__(self, func: Callable) -> Callable:
        """Use as decorator."""
        if asyncio.iscoroutinefunction(func):
            @functools.wraps(func)
            async def async_wrapper(*args, **kwargs):
                if self._waiting >= self.max_waiting:
                    raise BulkheadFull(f"Bulkhead '{self.name}' is full")
                
                self._waiting += 1
                try:
                    async with self._semaphore:
                        self._waiting -= 1
                        self._active += 1
                        try:
                            return await func(*args, **kwargs)
                        finally:
                            self._active -= 1
                except:
                    self._waiting -= 1
                    raise
            
            return async_wrapper
        else:
            @functools.wraps(func)
            def sync_wrapper(*args, **kwargs):
                sem = self._get_sync_semaphore()
                if not sem.acquire(blocking=False):
                    if self._waiting >= self.max_waiting:
                        raise BulkheadFull(f"Bulkhead '{self.name}' is full")
                    self._waiting += 1
                    sem.acquire()  # Block
                    self._waiting -= 1
                
                self._active += 1
                try:
                    return func(*args, **kwargs)
                finally:
                    self._active -= 1
                    sem.release()
            
            return sync_wrapper
    
    def get_status(self) -> dict:
        """Get bulkhead status."""
        return {
            "name": self.name,
            "max_concurrent": self.max_concurrent,
            "max_waiting": self.max_waiting,
            "active": self._active,
            "waiting": self._waiting
        }
