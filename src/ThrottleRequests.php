<?php

namespace Illuminate\Routing\Middleware;

use Closure;
use Illuminate\Cache\RateLimiter;
use Illuminate\Cache\RateLimiting\Unlimited;
use Illuminate\Http\Exceptions\HttpResponseException;
use Illuminate\Http\Exceptions\ThrottleRequestsException;
use Illuminate\Routing\Exceptions\MissingRateLimiterException;
use Illuminate\Support\InteractsWithTime;
use RuntimeException;
use Symfony\Component\HttpFoundation\Response;

use function Illuminate\Support\enum_value;

class ThrottleRequests
{
    use InteractsWithTime;

    /**
     * Rate limiter instance.
     */
    protected RateLimiter $limiter;

    /**
     * Indicates whether limiter keys should be hashed.
     */
    protected static bool $shouldHashKeys = true;

    /**
     * Create a new request throttler.
     */
    public function __construct(RateLimiter $limiter)
    {
        $this->limiter = $limiter;
    }

    /**
     * Specify the named rate limiter to use for the middleware.
     */
    public static function using($name): string
    {
        return static::class.':'.enum_value($name);
    }

    /**
     * Specify the rate limiter configuration for the middleware.
     *
     * @named-arguments-supported
     */
    public static function with(
        $maxAttempts = 60,
        $decayMinutes = 1,
        $prefix = ''
    ): string {
        return static::class.':'.implode(',', func_get_args());
    }

    /**
     * Handle an incoming request.
     *
     * @throws \Illuminate\Http\Exceptions\ThrottleRequestsException
     * @throws \Illuminate\Routing\Exceptions\MissingRateLimiterException
     */
    public function handle(
        $request,
        Closure $next,
        $maxAttempts = 60,
        $decayMinutes = 1,
        $prefix = ''
    ) {
        if ($this->shouldUseNamedLimiter($maxAttempts)) {
            $namedLimiter = $this->limiter->limiter($maxAttempts);

            if ($namedLimiter !== null) {
                return $this->handleRequestUsingNamedLimiter(
                    $request,
                    $next,
                    $maxAttempts,
                    $namedLimiter
                );
            }
        }

        $limit = $this->createLimit(
            key: $prefix.$this->resolveRequestSignature($request),
            maxAttempts: $this->resolveMaxAttempts($request, $maxAttempts),
            decaySeconds: max(0, (int) (60 * $decayMinutes))
        );

        return $this->handleRequest($request, $next, [$limit]);
    }

    /**
     * Determine whether the supplied argument represents a named limiter.
     */
    protected function shouldUseNamedLimiter($maxAttempts): bool
    {
        return is_string($maxAttempts) && func_num_args() === 1;
    }

    /**
     * Handle a request using a named limiter.
     */
    protected function handleRequestUsingNamedLimiter(
        $request,
        Closure $next,
        string $limiterName,
        Closure $limiter
    ) {
        $limiterResponse = $limiter($request);

        if ($limiterResponse instanceof Response) {
            return $limiterResponse;
        }

        if ($limiterResponse instanceof Unlimited) {
            return $next($request);
        }

        $limits = $this->normalizeNamedLimits(
            $limiterName,
            $limiterResponse
        );

        return $this->handleRequest($request, $next, $limits);
    }

    /**
     * Normalize the result returned by a named limiter.
     */
    protected function normalizeNamedLimits(
        string $limiterName,
        $limiterResponse
    ): array {
        $limits = is_array($limiterResponse)
            ? $limiterResponse
            : [$limiterResponse];

        $normalized = [];

        foreach ($limits as $limit) {
            $normalized[] = $this->createLimit(
                key: $this->formatNamedLimiterKey(
                    $limiterName,
                    $limit->key
                ),
                maxAttempts: $limit->maxAttempts,
                decaySeconds: $limit->decaySeconds,
                afterCallback: $limit->afterCallback ?? null,
                responseCallback: $limit->responseCallback ?? null
            );
        }

        return $normalized;
    }

    /**
     * Create the internal limiter representation.
     */
    protected function createLimit(
        string $key,
        int $maxAttempts,
        int $decaySeconds,
        ?callable $afterCallback = null,
        ?callable $responseCallback = null
    ): object {
        return (object) [
            'key' => $key,
            'maxAttempts' => $maxAttempts,
            'decaySeconds' => $decaySeconds,
            'afterCallback' => $afterCallback,
            'responseCallback' => $responseCallback,
        ];
    }

    /**
     * Handle the configured limits.
     *
     * The processing deliberately occurs in separate passes:
     *
     * 1. Validate every limiter before consuming any quota.
     * 2. Consume quota for unconditional limits.
     * 3. Execute the application.
     * 4. Consume conditional quotas.
     * 5. Add rate-limit response headers.
     *
     * @throws \Illuminate\Http\Exceptions\ThrottleRequestsException
     */
    protected function handleRequest(
        $request,
        Closure $next,
        array $limits
    ) {
        $this->ensureRequestIsWithinLimits($request, $limits);

        $this->hitUnconditionalLimits($limits);

        $response = $next($request);

        return $this->finalizeResponse($response, $limits);
    }

    /**
     * Verify all limits before allowing the request to proceed.
     */
    protected function ensureRequestIsWithinLimits(
        $request,
        array $limits
    ): void {
        foreach ($limits as $limit) {
            if (! $this->limiter->tooManyAttempts(
                $limit->key,
                $limit->maxAttempts
            )) {
                continue;
            }

            throw $this->buildException(
                $request,
                $limit->key,
                $limit->maxAttempts,
                $limit->responseCallback
            );
        }
    }

    /**
     * Increment limits that count the request immediately.
     */
    protected function hitUnconditionalLimits(array $limits): void
    {
        foreach ($limits as $limit) {
            if ($limit->afterCallback !== null) {
                continue;
            }

            $this->limiter->hit(
                $limit->key,
                $limit->decaySeconds
            );
        }
    }

    /**
     * Process conditional limits and decorate the response.
     */
    protected function finalizeResponse(
        Response $response,
        array $limits
    ): Response {
        foreach ($limits as $limit) {
            $this->hitConditionalLimit($limit, $response);

            $remainingAttempts = $this->calculateRemainingAttempts(
                $limit->key,
                $limit->maxAttempts
            );

            $response = $this->addHeaders(
                $response,
                $limit->maxAttempts,
                $remainingAttempts
            );
        }

        return $response;
    }

    /**
     * Increment a limit whose consumption depends on the response.
     */
    protected function hitConditionalLimit(
        object $limit,
        Response $response
    ): void {
        if ($limit->afterCallback === null) {
            return;
        }

        if (! ($limit->afterCallback)($response)) {
            return;
        }

        $this->limiter->hit(
            $limit->key,
            $limit->decaySeconds
        );
    }

    /**
     * Resolve the number of attempts for authenticated / guest users.
     *
     * @throws \Illuminate\Routing\Exceptions\MissingRateLimiterException
     */
    protected function resolveMaxAttempts(
        $request,
        $maxAttempts
    ): int {
        $user = $request->user();

        if (is_string($maxAttempts) && str_contains($maxAttempts, '|')) {
            [$guestAttempts, $authenticatedAttempts] = explode(
                '|',
                $maxAttempts,
                2
            );

            $maxAttempts = $user !== null
                ? $authenticatedAttempts
                : $guestAttempts;
        }

        if (
            ! is_numeric($maxAttempts)
            && $user !== null
            && $user->hasAttribute($maxAttempts)
        ) {
            $maxAttempts = $user->{$maxAttempts};
        }

        if (is_numeric($maxAttempts)) {
            return max(0, (int) $maxAttempts);
        }

        if ($user === null) {
            throw MissingRateLimiterException::forLimiter($maxAttempts);
        }

        throw MissingRateLimiterException::forLimiterAndUser(
            $maxAttempts,
            get_class($user)
        );
    }

    /**
     * Resolve the request signature.
     *
     * @throws \RuntimeException
     */
    protected function resolveRequestSignature($request): string
    {
        $user = $request->user();

        if ($user !== null) {
            return $this->formatIdentifier(
                (string) $user->getAuthIdentifier()
            );
        }

        $route = $request->route();

        if ($route !== null) {
            return $this->formatIdentifier(
                (string) $route->getDomain().'|'.$request->ip()
            );
        }

        throw new RuntimeException(
            'Unable to generate the request signature. Route unavailable.'
        );
    }

    /**
     * Create a "too many attempts" exception.
     */
    protected function buildException(
        $request,
        string $key,
        int $maxAttempts,
        $responseCallback = null
    ) {
        $retryAfter = $this->getTimeUntilNextRetry($key);

        $headers = $this->getHeaders(
            $maxAttempts,
            0,
            $retryAfter
        );

        if (is_callable($responseCallback)) {
            return new HttpResponseException(
                $responseCallback($request, $headers)
            );
        }

        return new ThrottleRequestsException(
            'Too Many Attempts.',
            null,
            $headers
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
     * Add rate-limit information to the response.
     */
    protected function addHeaders(
        Response $response,
        int $maxAttempts,
        int $remainingAttempts,
        ?int $retryAfter = null
    ): Response {
        $headers = $this->getHeaders(
            $maxAttempts,
            $remainingAttempts,
            $retryAfter,
            $response
        );

        if ($headers !== []) {
            $response->headers->add($headers);
        }

        return $response;
    }

    /**
     * Build rate-limit headers.
     */
    protected function getHeaders(
        int $maxAttempts,
        int $remainingAttempts,
        ?int $retryAfter = null,
        ?Response $response = null
    ): array {
        if (
            $response !== null
            && $this->responseHasStricterLimit(
                $response,
                $remainingAttempts
            )
        ) {
            return [];
        }

        $headers = [
            'X-RateLimit-Limit' => $maxAttempts,
            'X-RateLimit-Remaining' => max(0, $remainingAttempts),
        ];

        if ($retryAfter !== null) {
            $headers['Retry-After'] = $retryAfter;
            $headers['X-RateLimit-Reset'] = $this->availableAt($retryAfter);
        }

        return $headers;
    }

    /**
     * Determine whether the response already contains a stricter limit.
     */
    protected function responseHasStricterLimit(
        Response $response,
        int $remainingAttempts
    ): bool {
        $currentRemaining = $response->headers->get(
            'X-RateLimit-Remaining'
        );

        return $currentRemaining !== null
            && (int) $currentRemaining <= $remainingAttempts;
    }

    /**
     * Calculate the number of remaining attempts.
     */
    protected function calculateRemainingAttempts(
        string $key,
        int $maxAttempts,
        ?int $retryAfter = null
    ): int {
        if ($retryAfter !== null) {
            return 0;
        }

        return max(
            0,
            $this->limiter->retriesLeft($key, $maxAttempts)
        );
    }

    /**
     * Format a named limiter key.
     */
    protected function formatNamedLimiterKey(
        string $limiterName,
        $key
    ): string {
        $key = $limiterName.(string) $key;

        return self::$shouldHashKeys
            ? md5($key)
            : $limiterName.':'.(string) $key;
    }

    /**
     * Format an identifier according to the hashing configuration.
     */
    private function formatIdentifier($value): string
    {
        $value = (string) $value;

        return self::$shouldHashKeys
            ? sha1($value)
            : $value;
    }

    /**
     * Specify whether rate limiter keys should be hashed.
     */
    public static function shouldHashKeys(
        bool $shouldHashKeys = true
    ): void {
        self::$shouldHashKeys = $shouldHashKeys;
    }
}
