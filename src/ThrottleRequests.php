<?php

namespace Illuminate\Routing\Middleware;

use App\Contracts\AtomicRateLimiter;
use App\Contracts\RateLimitReservation;
use Closure;
use Illuminate\Cache\RateLimiter;
use Illuminate\Cache\RateLimiting\Unlimited;
use Illuminate\Http\Exceptions\HttpResponseException;
use Illuminate\Http\Exceptions\ThrottleRequestsException;
use Illuminate\Routing\Exceptions\MissingRateLimiterException;
use Illuminate\Support\Collection;
use Illuminate\Support\InteractsWithTime;
use RuntimeException;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\ServiceUnavailableHttpException;
use Throwable;

use function Illuminate\Support\enum_value;

class ThrottleRequests
{
    use InteractsWithTime;

    /**
     * Named limiter registry.
     */
    protected RateLimiter $limiter;

    /**
     * Atomic admission-control backend.
     */
    protected AtomicRateLimiter $atomicLimiter;

    /**
     * Never expose raw user IDs, IPs or route information in cache keys.
     */
    protected static bool $shouldHashKeys = true;

    public function __construct(
        RateLimiter $limiter,
        AtomicRateLimiter $atomicLimiter
    ) {
        $this->limiter = $limiter;
        $this->atomicLimiter = $atomicLimiter;
    }

    public static function using($name)
    {
        return static::class.':'.enum_value($name);
    }

    public static function with(
        $maxAttempts = 60,
        $decayMinutes = 1,
        $prefix = ''
    ) {
        return static::class.':'.implode(',', func_get_args());
    }

    /**
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
        if (
            is_string($maxAttempts)
            && func_num_args() === 3
            && ! is_null($limiter = $this->limiter->limiter($maxAttempts))
        ) {
            return $this->handleRequestUsingNamedLimiter(
                $request,
                $next,
                $maxAttempts,
                $limiter
            );
        }

        $maxAttempts = $this->resolveMaxAttempts(
            $request,
            $maxAttempts
        );

        $decaySeconds = $this->normalizeDecaySeconds($decayMinutes);

        return $this->handleRequest(
            $request,
            $next,
            [
                (object) [
                    'key' => $this->formatIdentifier(
                        'throttle|'.
                        $prefix.'|'.
                        $this->resolveRequestSignature($request)
                    ),
                    'maxAttempts' => $maxAttempts,
                    'decaySeconds' => $decaySeconds,
                    'afterCallback' => null,
                    'responseCallback' => null,
                ],
            ]
        );
    }

    protected function handleRequestUsingNamedLimiter(
        $request,
        Closure $next,
        $limiterName,
        Closure $limiter
    ) {
        $limiterResponse = $limiter($request);

        if ($limiterResponse instanceof Response) {
            return $limiterResponse;
        }

        /*
         * Unlimited is an explicit application configuration.
         * It is therefore allowed to bypass admission control.
         */
        if ($limiterResponse instanceof Unlimited) {
            return $next($request);
        }

        $limits = Collection::wrap($limiterResponse)
            ->map(function ($limit) use ($limiterName) {
                $maxAttempts = $this->normalizeMaxAttempts(
                    $limit->maxAttempts
                );

                $decaySeconds = $this->normalizeDecaySecondsValue(
                    $limit->decaySeconds
                );

                /*
                 * Always namespace and cryptographically hash the key.
                 *
                 * Do not use MD5 here. A SHA-256 digest gives a fixed-size
                 * opaque key and prevents identifiers/IPs from leaking into
                 * the cache namespace.
                 */
                $key = $this->formatIdentifier(
                    'named|'.
                    (string) $limiterName.'|'.
                    (string) $limit->key
                );

                return (object) [
                    'key' => $key,
                    'maxAttempts' => $maxAttempts,
                    'decaySeconds' => $decaySeconds,
                    'afterCallback' => $limit->afterCallback,
                    'responseCallback' => $limit->responseCallback,
                ];
            })
            ->all();

        return $this->handleRequest(
            $request,
            $next,
            $limits
        );
    }

    /**
     * Reserve EVERY applicable limit before entering the application.
     *
     * There is deliberately no call to tooManyAttempts() followed by hit().
     */
    protected function handleRequest(
        $request,
        Closure $next,
        array $limits
    ) {
        $reservations = [];

        /*
         * ---------------------------------------------------------------
         * PHASE 1: ADMISSION CONTROL
         * ---------------------------------------------------------------
         *
         * Everything in this phase happens before $next().
         */
        foreach ($limits as $index => $limit) {
            try {
                $reservation = $this->atomicLimiter->acquire(
                    $limit->key,
                    $limit->maxAttempts,
                    $limit->decaySeconds
                );
            } catch (Throwable $e) {
                /*
                 * FAIL CLOSED.
                 *
                 * No cache/Redis/backend exception is propagated to the
                 * HTTP client and $next() is NEVER executed.
                 */
                $this->releaseReservations($limits, $reservations);

                throw $this->buildLimiterUnavailableException();
            }

            if (! $reservation->allowed) {
                /*
                 * This request must not consume quotas belonging to limits
                 * that were successfully reserved earlier in this loop.
                 */
                $this->releaseReservations($limits, $reservations);

                throw $this->buildException(
                    $request,
                    $reservation,
                    $limit->responseCallback
                );
            }

            $reservations[$index] = $reservation;
        }

        /*
         * ---------------------------------------------------------------
         * PHASE 2: APPLICATION
         * ---------------------------------------------------------------
         *
         * Reaching this statement proves every limiter granted admission.
         */
        try {
            $response = $next($request);
        } catch (Throwable $e) {
            /*
             * Do NOT refund reservations when application code throws.
             *
             * Otherwise an attacker may intentionally trigger errors to
             * obtain effectively unlimited expensive requests.
             */
            throw $e;
        }

        /*
         * ---------------------------------------------------------------
         * PHASE 3: CONDITIONAL ACCOUNTING
         * ---------------------------------------------------------------
         *
         * For afterCallback limiters we already reserved capacity before
         * executing the application.
         *
         * If the response should NOT count, refund afterwards.
         */
        foreach ($limits as $index => $limit) {
            if ($limit->afterCallback) {
                $shouldCount = true;

                try {
                    $shouldCount = (bool) ($limit->afterCallback)($response);
                } catch (Throwable $e) {
                    /*
                     * Fail closed:
                     *
                     * failure of the callback means the reservation remains
                     * consumed. An attacker cannot bypass throttling by
                     * causing the callback to fail.
                     */
                    $shouldCount = true;
                }

                if (! $shouldCount) {
                    try {
                        $this->atomicLimiter->release($limit->key);
                    } catch (Throwable $e) {
                        /*
                         * Conservative failure:
                         * leave the attempt charged.
                         *
                         * Never expose backend details.
                         */
                    }
                }
            }

            $reservation = $reservations[$index];

            $response = $this->addHeaders(
                $response,
                $reservation->limit,
                $reservation->remaining
            );
        }

        return $response;
    }

    protected function resolveMaxAttempts(
        $request,
        $maxAttempts
    ) {
        if (
            is_string($maxAttempts)
            && str_contains($maxAttempts, '|')
        ) {
            $parts = explode('|', $maxAttempts, 2);

            $maxAttempts = $parts[
                $request->user() ? 1 : 0
            ];
        }

        if (
            ! is_numeric($maxAttempts)
            && $request->user()?->hasAttribute($maxAttempts)
        ) {
            $maxAttempts = $request->user()->{$maxAttempts};
        }

        if (! is_numeric($maxAttempts)) {
            is_null($request->user())
                ? throw MissingRateLimiterException::forLimiter(
                    $maxAttempts
                )
                : throw MissingRateLimiterException::forLimiterAndUser(
                    $maxAttempts,
                    get_class($request->user())
                );
        }

        return $this->normalizeMaxAttempts($maxAttempts);
    }

    /**
     * Resolve a canonical, unambiguous client identity.
     *
     * Raw values are never returned.
     */
    protected function resolveRequestSignature($request)
    {
        if ($user = $request->user()) {
            $identifier = $user->getAuthIdentifier();

            if (
                ! is_string($identifier)
                && ! is_int($identifier)
            ) {
                throw new RuntimeException(
                    'Unable to generate request signature.'
                );
            }

            $identifier = trim((string) $identifier);

            if ($identifier === '' || strlen($identifier) > 512) {
                throw new RuntimeException(
                    'Unable to generate request signature.'
                );
            }

            /*
             * Include the model class to prevent IDs from different
             * authentication domains colliding.
             */
            return $this->formatIdentifier(
                'authenticated|'.
                get_class($user).'|'.
                $identifier
            );
        }

        $route = $request->route();

        if (! $route) {
            throw new RuntimeException(
                'Unable to generate request signature.'
            );
        }

        /*
         * request->ip() must already reflect Laravel/Symfony trusted-proxy
         * configuration. Never manually trust X-Forwarded-For here.
         */
        $ip = $request->ip();

        if (! is_string($ip)) {
            throw new RuntimeException(
                'Unable to generate request signature.'
            );
        }

        $ip = trim($ip);

        if (
            filter_var(
                $ip,
                FILTER_VALIDATE_IP,
                FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6
            ) === false
        ) {
            /*
             * Invalid/spoofed/ambiguous client address => fail closed.
             */
            throw new RuntimeException(
                'Unable to generate request signature.'
            );
        }

        $packedIp = @inet_pton($ip);

        if ($packedIp === false) {
            throw new RuntimeException(
                'Unable to generate request signature.'
            );
        }

        /*
         * inet_pton() canonicalizes equivalent textual IPv6
         * representations before hashing.
         */
        $canonicalIp = bin2hex($packedIp);

        $domain = strtolower(
            trim((string) $route->getDomain())
        );

        /*
         * Domain is only a namespace. The security identity is the
         * canonical address after trusted-proxy resolution.
         */
        return $this->formatIdentifier(
            'anonymous|'.
            $domain.'|'.
            $canonicalIp
        );
    }

    protected function buildException(
        $request,
        RateLimitReservation $reservation,
        $responseCallback = null
    ) {
        /*
         * Clamp values returned by the backend before reflecting them
         * into HTTP headers.
         */
        $retryAfter = max(
            1,
            min(
                $reservation->retryAfter,
                86400
            )
        );

        $headers = $this->getHeaders(
            $reservation->limit,
            0,
            $retryAfter
        );

        if (is_callable($responseCallback)) {
            $response = $responseCallback(
                $request,
                $headers
            );

            /*
             * Security headers cannot be silently removed by the custom
             * response.
             */
            $response->headers->set(
                'X-RateLimit-Limit',
                (string) $reservation->limit
            );

            $response->headers->set(
                'X-RateLimit-Remaining',
                '0'
            );

            $response->headers->set(
                'Retry-After',
                (string) $retryAfter
            );

            $response->headers->set(
                'X-RateLimit-Reset',
                (string) $this->availableAt($retryAfter)
            );

            return new HttpResponseException($response);
        }

        /*
         * Generic public message:
         * no key, cache driver, host, exception or Redis details.
         */
        return new ThrottleRequestsException(
            'Too Many Attempts.',
            null,
            $headers
        );
    }

    /**
     * Backend failure is different from an actual 429.
     *
     * Return 503, still fail-closed, and disclose no infrastructure
     * information.
     */
    protected function buildLimiterUnavailableException()
    {
        return new ServiceUnavailableHttpException(
            5,
            'Service temporarily unavailable.'
        );
    }

    protected function addHeaders(
        Response $response,
        $maxAttempts,
        $remainingAttempts,
        $retryAfter = null
    ) {
        $response->headers->add(
            $this->getHeaders(
                $maxAttempts,
                $remainingAttempts,
                $retryAfter,
                $response
            )
        );

        return $response;
    }

    protected function getHeaders(
        $maxAttempts,
        $remainingAttempts,
        $retryAfter = null,
        ?Response $response = null
    ) {
        $maxAttempts = max(1, (int) $maxAttempts);

        $remainingAttempts = max(
            0,
            min(
                $maxAttempts,
                (int) $remainingAttempts
            )
        );

        /*
         * If another limiter already supplied a more restrictive
         * Remaining value, preserve it.
         */
        if (
            $response
            && $response->headers->has(
                'X-RateLimit-Remaining'
            )
            && (int) $response->headers->get(
                'X-RateLimit-Remaining'
            ) <= $remainingAttempts
        ) {
            return [];
        }

        $headers = [
            'X-RateLimit-Limit' => $maxAttempts,
            'X-RateLimit-Remaining' => $remainingAttempts,
        ];

        if ($retryAfter !== null) {
            $retryAfter = max(
                1,
                min(
                    86400,
                    (int) $retryAfter
                )
            );

            $headers['Retry-After'] = $retryAfter;

            /*
             * Public timestamp only. No backend/cache metadata.
             */
            $headers['X-RateLimit-Reset'] =
                $this->availableAt($retryAfter);
        }

        return $headers;
    }

    /**
     * Release reservations acquired before a later limiter rejected.
     */
    private function releaseReservations(
        array $limits,
        array $reservations
    ): void {
        foreach (
            array_reverse(
                array_keys($reservations)
            ) as $index
        ) {
            try {
                $this->atomicLimiter->release(
                    $limits[$index]->key
                );
            } catch (Throwable $e) {
                /*
                 * Conservative behavior:
                 * leaking one quota unit is safer than allowing an
                 * unaccounted request through.
                 */
            }
        }
    }

    private function normalizeMaxAttempts($value): int
    {
        if (
            ! is_numeric($value)
            || (int) $value < 1
            || (int) $value > 1_000_000
        ) {
            throw new RuntimeException(
                'Invalid rate limiter configuration.'
            );
        }

        return (int) $value;
    }

    private function normalizeDecaySeconds(
        $decayMinutes
    ): int {
        if (
            ! is_numeric($decayMinutes)
            || (float) $decayMinutes <= 0
        ) {
            throw new RuntimeException(
                'Invalid rate limiter configuration.'
            );
        }

        $seconds = (int) ceil(
            (float) $decayMinutes * 60
        );

        return $this->normalizeDecaySecondsValue(
            $seconds
        );
    }

    private function normalizeDecaySecondsValue(
        $seconds
    ): int {
        if (
            ! is_numeric($seconds)
            || (int) $seconds < 1
            || (int) $seconds > 86400
        ) {
            throw new RuntimeException(
                'Invalid rate limiter configuration.'
            );
        }

        return (int) $seconds;
    }

    /**
     * SHA-256 produces fixed-size opaque keys.
     *
     * Disabling hashing is intentionally no longer supported for
     * production safety.
     */
    private function formatIdentifier($value)
    {
        return hash(
            'sha256',
            (string) $value
        );
    }

    /**
     * Kept only for backwards API compatibility.
     *
     * Raw identifiers are no longer permitted.
     */
    public static function shouldHashKeys(
        bool $shouldHashKeys = true
    ) {
        if (! $shouldHashKeys) {
            throw new RuntimeException(
                'Disabling rate limiter key hashing is not permitted.'
            );
        }

        self::$shouldHashKeys = true;
    }
}
