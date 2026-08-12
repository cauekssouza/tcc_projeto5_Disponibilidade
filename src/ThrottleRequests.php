<?php

namespace Illuminate\Routing\Middleware;

use Closure;
use Illuminate\Cache\RateLimiter;
use Illuminate\Cache\RateLimiting\Unlimited;
use Illuminate\Http\Exceptions\HttpResponseException;
use Illuminate\Http\Exceptions\ThrottleRequestsException;
use Illuminate\Http\Request;
use Illuminate\Routing\Exceptions\MissingRateLimiterException;
use Illuminate\Support\InteractsWithTime;
use RuntimeException;
use Symfony\Component\HttpFoundation\Response;
use UnitEnum;

use function Illuminate\Support\enum_value;

class ThrottleRequests
{
    use InteractsWithTime;

    /**
     * Indicates whether rate limiter keys should be hashed.
     */
    protected static bool $shouldHashKeys = true;

    public function __construct(
        protected RateLimiter $limiter,
    ) {
    }

    /**
     * Specify the named rate limiter to use for the middleware.
     */
    public static function using(UnitEnum|string $name): string
    {
        return static::class.':'.enum_value($name);
    }

    /**
     * Specify the rate limiter configuration for the middleware.
     *
     * @named-arguments-supported
     */
    public static function with(
        int $maxAttempts = 60,
        int $decayMinutes = 1,
        string $prefix = '',
    ): string {
        // func_get_args() is intentionally retained to preserve the
        // middleware-string behavior when optional arguments are omitted.
        return static::class.':'.implode(',', func_get_args());
    }

    /**
     * Handle an incoming request.
     *
     * @throws ThrottleRequestsException
     * @throws MissingRateLimiterException
     */
    public function handle(
        Request $request,
        Closure $next,
        int|string $maxAttempts = 60,
        int|float $decayMinutes = 1,
        string $prefix = '',
    ): Response {
        if (
            is_string($maxAttempts)
            && func_num_args() === 3
            && ($limiter = $this->limiter->limiter($maxAttempts)) !== null
        ) {
            return $this->handleRequestUsingNamedLimiter(
                $request,
                $next,
                $maxAttempts,
                $limiter,
            );
        }

        $limit = (object) [
            'key' => $prefix.$this->resolveRequestSignature($request),
            'maxAttempts' => $this->resolveMaxAttempts($request, $maxAttempts),
            'decaySeconds' => 60 * $decayMinutes,
            'afterCallback' => null,
            'responseCallback' => null,
        ];

        return $this->handleRequest($request, $next, [$limit]);
    }

    /**
     * Handle a request using a named rate limiter.
     *
     * @throws ThrottleRequestsException
     */
    protected function handleRequestUsingNamedLimiter(
        Request $request,
        Closure $next,
        string $limiterName,
        Closure $limiter,
    ): Response {
        $limiterResponse = $limiter($request);

        if ($limiterResponse instanceof Response) {
            return $limiterResponse;
        }

        if ($limiterResponse instanceof Unlimited) {
            return $next($request);
        }

        $rawLimits = is_iterable($limiterResponse)
            ? $limiterResponse
            : [$limiterResponse];

        $limits = [];

        foreach ($rawLimits as $limit) {
            $limits[] = (object) [
                'key' => $this->formatNamedLimiterKey($limiterName, $limit->key),
                'maxAttempts' => $limit->maxAttempts,
                'decaySeconds' => $limit->decaySeconds,
                'afterCallback' => $limit->afterCallback,
                'responseCallback' => $limit->responseCallback,
            ];
        }

        return $this->handleRequest($request, $next, $limits);
    }

    /**
     * Handle an incoming request against the given limits.
     *
     * @param array<int, object> $limits
     *
     * @throws ThrottleRequestsException
     */
    protected function handleRequest(
        Request $request,
        Closure $next,
        array $limits,
    ): Response {
        // Validate every limiter before incrementing any of them.
        foreach ($limits as $limit) {
            if ($this->limiter->tooManyAttempts(
                $limit->key,
                $limit->maxAttempts,
            )) {
                throw $this->buildException(
                    $request,
                    $limit->key,
                    $limit->maxAttempts,
                    $limit->responseCallback,
                );
            }
        }

        // Limits without an "after" callback count the attempt immediately.
        foreach ($limits as $limit) {
            if ($limit->afterCallback === null) {
                $this->limiter->hit(
                    $limit->key,
                    $limit->decaySeconds,
                );
            }
        }

        $response = $next($request);

        foreach ($limits as $limit) {
            if (
                $limit->afterCallback !== null
                && ($limit->afterCallback)($response)
            ) {
                $this->limiter->hit(
                    $limit->key,
                    $limit->decaySeconds,
                );
            }

            $response = $this->addHeaders(
                $response,
                $limit->maxAttempts,
                $this->calculateRemainingAttempts(
                    $limit->key,
                    $limit->maxAttempts,
                ),
            );
        }

        return $response;
    }

    /**
     * Resolve the number of allowed attempts.
     *
     * @throws MissingRateLimiterException
     */
    protected function resolveMaxAttempts(
        Request $request,
        int|string $maxAttempts,
    ): int {
        $user = $request->user();

        if (is_string($maxAttempts) && str_contains($maxAttempts, '|')) {
            [$guestAttempts, $authenticatedAttempts] = explode(
                '|',
                $maxAttempts,
                2,
            );

            $maxAttempts = $user
                ? $authenticatedAttempts
                : $guestAttempts;
        }

        if (
            ! is_numeric($maxAttempts)
            && $user?->hasAttribute($maxAttempts)
        ) {
            $maxAttempts = $user->{$maxAttempts};
        }

        if (is_numeric($maxAttempts)) {
            return (int) $maxAttempts;
        }

        if ($user === null) {
            throw MissingRateLimiterException::forLimiter($maxAttempts);
        }

        throw MissingRateLimiterException::forLimiterAndUser(
            $maxAttempts,
            $user::class,
        );
    }

    /**
     * Resolve the request signature.
     *
     * @throws RuntimeException
     */
    protected function resolveRequestSignature(Request $request): string
    {
        if (($user = $request->user()) !== null) {
            return $this->formatIdentifier(
                (string) $user->getAuthIdentifier(),
            );
        }

        if (($route = $request->route()) !== null) {
            return $this->formatIdentifier(
                $route->getDomain().'|'.$request->ip(),
            );
        }

        throw new RuntimeException(
            'Unable to generate the request signature. Route unavailable.',
        );
    }

    /**
     * Create a "too many attempts" exception.
     */
    protected function buildException(
        Request $request,
        string $key,
        int $maxAttempts,
        ?callable $responseCallback = null,
    ): ThrottleRequestsException|HttpResponseException {
        $retryAfter = $this->getTimeUntilNextRetry($key);

        $headers = $this->getHeaders(
            $maxAttempts,
            $this->calculateRemainingAttempts(
                $key,
                $maxAttempts,
                $retryAfter,
            ),
            $retryAfter,
        );

        if (is_callable($responseCallback)) {
            return new HttpResponseException(
                $responseCallback($request, $headers),
            );
        }

        return new ThrottleRequestsException(
            'Too Many Attempts.',
            null,
            $headers,
        );
    }

    /**
     * Get the number of seconds until the next retry.
     */
    protected function getTimeUntilNextRetry(string $key): int
    {
        return $this->limiter->availableIn($key);
    }

    /**
     * Add rate-limit information to the response headers.
     */
    protected function addHeaders(
        Response $response,
        int $maxAttempts,
        int $remainingAttempts,
        ?int $retryAfter = null,
    ): Response {
        $response->headers->add(
            $this->getHeaders(
                $maxAttempts,
                $remainingAttempts,
                $retryAfter,
                $response,
            ),
        );

        return $response;
    }

    /**
     * Get the rate-limit headers.
     *
     * @return array<string, int>
     */
    protected function getHeaders(
        int $maxAttempts,
        int $remainingAttempts,
        ?int $retryAfter = null,
        ?Response $response = null,
    ): array {
        $currentRemaining = $response?->headers->get(
            'X-RateLimit-Remaining',
        );

        if (
            $currentRemaining !== null
            && (int) $currentRemaining <= $remainingAttempts
        ) {
            return [];
        }

        $headers = [
            'X-RateLimit-Limit' => $maxAttempts,
            'X-RateLimit-Remaining' => $remainingAttempts,
        ];

        if ($retryAfter !== null) {
            $headers['Retry-After'] = $retryAfter;
            $headers['X-RateLimit-Reset'] = $this->availableAt($retryAfter);
        }

        return $headers;
    }

    /**
     * Calculate the number of remaining attempts.
     */
    protected function calculateRemainingAttempts(
        string $key,
        int $maxAttempts,
        ?int $retryAfter = null,
    ): int {
        return $retryAfter === null
            ? $this->limiter->retriesLeft($key, $maxAttempts)
            : 0;
    }

    /**
     * Format a request identifier according to the hashing configuration.
     */
    private function formatIdentifier(string $value): string
    {
        return static::$shouldHashKeys
            ? sha1($value)
            : $value;
    }

    /**
     * Format a named limiter key.
     *
     * md5() is intentionally preserved here so existing applications don't
     * suddenly generate different cache keys after upgrading this class.
     */
    private function formatNamedLimiterKey(
        string $limiterName,
        string $key,
    ): string {
        return static::$shouldHashKeys
            ? md5($limiterName.$key)
            : $limiterName.':'.$key;
    }

    /**
     * Specify whether rate limiter keys should be hashed.
     */
    public static function shouldHashKeys(bool $shouldHashKeys = true): void
    {
        static::$shouldHashKeys = $shouldHashKeys;
    }
}
