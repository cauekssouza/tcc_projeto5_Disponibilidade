<?php

namespace Illuminate\Routing\Middleware;

use Closure;
use Illuminate\Cache\RateLimiter;
use Illuminate\Cache\RateLimiting\Unlimited;
use Illuminate\Contracts\Redis\Factory as Redis;
use Illuminate\Http\Exceptions\HttpResponseException;
use Illuminate\Http\Exceptions\ThrottleRequestsException;
use Illuminate\Redis\Limiters\DurationLimiter;
use Illuminate\Routing\Exceptions\MissingRateLimiterException;
use Illuminate\Support\Collection;
use Illuminate\Support\InteractsWithTime;
use InvalidArgumentException;
use RuntimeException;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

use function Illuminate\Support\enum_value;

class ThrottleRequests
{
    use InteractsWithTime;

    /**
     * Used only for resolving named limiters.
     */
    protected RateLimiter $limiter;

    /**
     * Redis is deliberately required for the admission gate because
     * the check + consume operation must be atomic.
     */
    protected Redis $redis;

    /**
     * Security hardened mode: rate-limit keys are never stored raw.
     */
    protected static bool $shouldHashKeys = true;

    public function __construct(RateLimiter $limiter, Redis $redis)
    {
        $this->limiter = $limiter;
        $this->redis = $redis;
    }

    public static function using($name)
    {
        return static::class.':'.enum_value($name);
    }

    public static function with($maxAttempts = 60, $decayMinutes = 1, $prefix = '')
    {
        return static::class.':'.implode(',', func_get_args());
    }

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

        $maxAttempts = $this->resolveMaxAttempts($request, $maxAttempts);
        $decaySeconds = $this->normalizeDecaySeconds($decayMinutes * 60);

        return $this->handleRequest(
            $request,
            $next,
            [
                (object) [
                    'key' => $this->formatIdentifier(
                        'default|'.
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

        if ($limiterResponse instanceof Unlimited) {
            return $next($request);
        }

        $limits = Collection::wrap($limiterResponse)
            ->map(function ($limit) use ($limiterName) {
                return (object) [
                    /*
                     * Length-delimited / typed material is hashed instead
                     * of using MD5 or concatenating attacker-controlled
                     * components ambiguously.
                     */
                    'key' => $this->formatIdentifier(
                        'named|'.
                        strlen((string) $limiterName).':'.
                        $limiterName.'|'.
                        strlen((string) $limit->key).':'.
                        $limit->key
                    ),
                    'maxAttempts' => $this->normalizeMaxAttempts(
                        $limit->maxAttempts
                    ),
                    'decaySeconds' => $this->normalizeDecaySeconds(
                        $limit->decaySeconds
                    ),
                    'afterCallback' => $limit->afterCallback,
                    'responseCallback' => $limit->responseCallback,
                ];
            })
            ->all();

        return $this->handleRequest($request, $next, $limits);
    }

    /**
     * Admission control.
     *
     * SECURITY PROPERTY:
     *
     * There is no:
     *
     *     tooManyAttempts();
     *     ...
     *     hit();
     *
     * sequence here.
     *
     * Each limit is reserved atomically BEFORE $next() is executed.
     */
    protected function handleRequest($request, Closure $next, array $limits)
    {
        $reservations = [];

        foreach ($limits as $limit) {
            $this->validateLimit($limit);

            try {
                $reservation = $this->acquire($limit);
            } catch (Throwable $e) {
                /*
                 * Fail closed.
                 *
                 * A cache/Redis outage must never turn rate limiting into
                 * "unlimited access".
                 *
                 * Do not expose $e, connection names, Redis addresses,
                 * cache keys, drivers, stack traces, etc.
                 */
                throw $this->buildLimiterUnavailableException();
            }

            if (! $reservation->allowed) {
                /*
                 * Anything already reserved for this request is refunded
                 * because the application itself will not execute.
                 *
                 * A refund is window-bound to prevent decrementing a newer
                 * rate-limit window.
                 */
                $this->rollbackReservations($reservations);

                throw $this->buildException(
                    $request,
                    $limit->maxAttempts,
                    $limit->responseCallback,
                    $reservation->decaysAt
                );
            }

            $reservations[] = (object) [
                'limit' => $limit,
                'decaysAt' => $reservation->decaysAt,
                'remaining' => $reservation->remaining,
            ];
        }

        /*
         * CRITICAL:
         *
         * $next() occurs ONLY after every admission token has been acquired.
         *
         * An over-limit request therefore cannot reach controllers,
         * password hashing, ORM, SQL, external APIs, etc.
         */
        $response = $next($request);

        foreach ($reservations as $reservation) {
            $limit = $reservation->limit;

            /*
             * "after" limiters traditionally decide whether a completed
             * response should consume quota.
             *
             * For availability we reserve BEFORE executing the application,
             * then refund afterwards if the callback says not to count it.
             *
             * This is deliberately conservative under concurrency.
             */
            if ($limit->afterCallback) {
                $shouldKeepReservation = false;

                try {
                    $shouldKeepReservation =
                        (bool) ($limit->afterCallback)($response);
                } catch (Throwable $e) {
                    /*
                     * Fail closed: callback failure keeps the reservation.
                     *
                     * Never turn an application error into additional
                     * rate-limit capacity.
                     */
                    $shouldKeepReservation = true;
                }

                if (! $shouldKeepReservation) {
                    $this->releaseReservation(
                        $limit->key,
                        $reservation->decaysAt
                    );
                }
            }

            $response = $this->addHeaders(
                $response,
                $limit->maxAttempts,
                max(0, (int) $reservation->remaining)
            );
        }

        return $response;
    }

    /**
     * Atomically consumes one slot and returns the decision generated by
     * the same Redis/Lua operation.
     */
    protected function acquire(object $limit): object
    {
        $limiter = new DurationLimiter(
            $this->redis->connection(),
            $limit->key,
            $limit->maxAttempts,
            $limit->decaySeconds
        );

        $allowed = $limiter->acquire();

        return (object) [
            'allowed' => (bool) $allowed,
            'remaining' => max(0, (int) $limiter->remaining),
            'decaysAt' => (int) $limiter->decaysAt,
        ];
    }

    /**
     * Refund a pre-admission reservation, but only if Redis is still
     * representing exactly the same time window.
     *
     * This prevents an old request from decrementing a newly-created window.
     */
    protected function releaseReservation(string $key, int $expectedDecaysAt): void
    {
        try {
            $this->redis->connection()->eval(
                <<<'LUA'
local currentEnd = redis.call('HGET', KEYS[1], 'end')

if not currentEnd then
    return 0
end

if tonumber(currentEnd) ~= tonumber(ARGV[1]) then
    return 0
end

local count = tonumber(redis.call('HGET', KEYS[1], 'count') or '0')

if count <= 0 then
    return 0
end

redis.call('HINCRBY', KEYS[1], 'count', -1)

return 1
LUA,
                1,
                $key,
                $expectedDecaysAt
            );
        } catch (Throwable $e) {
            /*
             * Deliberately do nothing.
             *
             * Failure to refund leaves the system MORE restrictive,
             * never less restrictive. That is the fail-closed outcome.
             */
        }
    }

    protected function rollbackReservations(array $reservations): void
    {
        foreach ($reservations as $reservation) {
            $this->releaseReservation(
                $reservation->limit->key,
                $reservation->decaysAt
            );
        }
    }

    protected function resolveMaxAttempts($request, $maxAttempts)
    {
        if (
            is_string($maxAttempts)
            && str_contains($maxAttempts, '|')
        ) {
            $maxAttempts = explode(
                '|',
                $maxAttempts,
                2
            )[$request->user() ? 1 : 0];
        }

        if (
            ! is_numeric($maxAttempts)
            && $request->user()?->hasAttribute($maxAttempts)
        ) {
            $maxAttempts = $request->user()->{$maxAttempts};
        }

        if (! is_numeric($maxAttempts)) {
            is_null($request->user())
                ? throw MissingRateLimiterException::forLimiter($maxAttempts)
                : throw MissingRateLimiterException::forLimiterAndUser(
                    $maxAttempts,
                    get_class($request->user())
                );
        }

        return $this->normalizeMaxAttempts($maxAttempts);
    }

    protected function normalizeMaxAttempts($value): int
    {
        if (
            ! is_numeric($value)
            || (int) $value < 1
            || (int) $value > 1_000_000
        ) {
            throw new InvalidArgumentException(
                'Invalid rate limit configuration.'
            );
        }

        return (int) $value;
    }

    protected function normalizeDecaySeconds($value): int
    {
        if (
            ! is_numeric($value)
            || ! is_finite((float) $value)
        ) {
            throw new InvalidArgumentException(
                'Invalid rate limit configuration.'
            );
        }

        /*
         * Avoid zero/negative TTL and arbitrarily huge retention.
         * Adapt the upper bound to your business requirement if necessary.
         */
        $seconds = (int) ceil((float) $value);

        if ($seconds < 1 || $seconds > 86_400) {
            throw new InvalidArgumentException(
                'Invalid rate limit configuration.'
            );
        }

        return $seconds;
    }

    protected function validateLimit(object $limit): void
    {
        $limit->maxAttempts = $this->normalizeMaxAttempts(
            $limit->maxAttempts
        );

        $limit->decaySeconds = $this->normalizeDecaySeconds(
            $limit->decaySeconds
        );

        if (
            ! isset($limit->key)
            || ! is_string($limit->key)
            || $limit->key === ''
            || strlen($limit->key) > 512
        ) {
            throw new InvalidArgumentException(
                'Invalid rate limit configuration.'
            );
        }
    }

    /**
     * Create a stable, strict request identity.
     *
     * Never directly consumes X-Forwarded-For / Forwarded / X-Real-IP.
     * Laravel/Symfony may only use those after TrustedProxy configuration
     * has established which reverse proxies are trusted.
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

            $identifier = (string) $identifier;

            if (
                $identifier === ''
                || strlen($identifier) > 256
                || preg_match('/[\x00-\x1F\x7F]/', $identifier)
            ) {
                throw new RuntimeException(
                    'Unable to generate request signature.'
                );
            }

            /*
             * Class is included as an explicit namespace so IDs such as "42"
             * from two independently authenticated models cannot collide.
             */
            return $this->formatIdentifier(
                'auth|'.
                strlen(get_class($user)).':'.
                get_class($user).'|'.
                strlen($identifier).':'.
                $identifier
            );
        }

        if (! $request->route()) {
            throw new RuntimeException(
                'Unable to generate request signature.'
            );
        }

        $ip = $this->canonicalizeIp($request->ip());

        /*
         * getDomain() is route configuration, not the Host header supplied
         * directly by an untrusted client.
         */
        $domain = (string) ($request->route()->getDomain() ?? '*');

        return $this->formatIdentifier(
            'guest|'.
            strlen($domain).':'.
            $domain.'|'.
            strlen($ip).':'.
            $ip
        );
    }

    /**
     * Canonicalize IP addresses so textual aliases cannot generate
     * distinct rate-limit identities.
     */
    protected function canonicalizeIp($ip): string
    {
        if (
            ! is_string($ip)
            || $ip === ''
            || strlen($ip) > 45
            || filter_var($ip, FILTER_VALIDATE_IP) === false
        ) {
            throw new RuntimeException(
                'Unable to generate request signature.'
            );
        }

        $packed = @inet_pton($ip);

        if ($packed === false) {
            throw new RuntimeException(
                'Unable to generate request signature.'
            );
        }

        /*
         * Normalize IPv4-mapped IPv6:
         *
         *   ::ffff:192.0.2.10
         *
         * to:
         *
         *   192.0.2.10
         *
         * preventing two textual families from becoming two buckets for
         * the same IPv4 endpoint.
         */
        if (
            strlen($packed) === 16
            && substr($packed, 0, 12)
                === str_repeat("\x00", 10)."\xff\xff"
        ) {
            $packed = substr($packed, 12);
        }

        $canonical = @inet_ntop($packed);

        if ($canonical === false) {
            throw new RuntimeException(
                'Unable to generate request signature.'
            );
        }

        return strtolower($canonical);
    }

    protected function buildException(
        $request,
        int $maxAttempts,
        $responseCallback,
        int $decaysAt
    ) {
        /*
         * Calculate from the atomic operation's result rather than doing a
         * second cache query, eliminating another race / backend dependency.
         */
        $retryAfter = max(
            1,
            (int) ceil($decaysAt - $this->currentTime())
        );

        $headers = $this->getHeaders(
            $maxAttempts,
            0,
            $retryAfter
        );

        return is_callable($responseCallback)
            ? new HttpResponseException(
                $responseCallback($request, $headers)
            )
            : new ThrottleRequestsException(
                'Too Many Requests.',
                null,
                $headers
            );
    }

    /**
     * Backend failure != quota exhaustion.
     *
     * Use 503, not 429, but remain fail-closed.
     */
    protected function buildLimiterUnavailableException(): HttpResponseException
    {
        return new HttpResponseException(
            new Response(
                'Service temporarily unavailable.',
                Response::HTTP_SERVICE_UNAVAILABLE,
                [
                    'Retry-After' => '1',
                    'Cache-Control' => 'no-store',
                ]
            )
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
            min($maxAttempts, (int) $remainingAttempts)
        );

        if (
            $response
            && $response->headers->has('X-RateLimit-Remaining')
            && (int) $response->headers->get('X-RateLimit-Remaining')
                <= $remainingAttempts
        ) {
            return [];
        }

        $headers = [
            'X-RateLimit-Limit' => (string) $maxAttempts,
            'X-RateLimit-Remaining' => (string) $remainingAttempts,
        ];

        if ($retryAfter !== null) {
            $retryAfter = max(1, (int) ceil($retryAfter));

            $headers['Retry-After'] = (string) $retryAfter;
            $headers['X-RateLimit-Reset'] = (string) (
                $this->currentTime() + $retryAfter
            );
        }

        return $headers;
    }

    /**
     * SHA-256 rather than MD5/SHA-1.
     *
     * The material being hashed already has explicit namespaces and
     * length delimiters, avoiding ambiguous concatenation.
     */
    private function formatIdentifier($value)
    {
        if (! is_string($value) || strlen($value) > 2048) {
            throw new RuntimeException(
                'Unable to generate request signature.'
            );
        }

        return hash('sha256', $value);
    }

    /**
     * Kept for source compatibility, but hardened mode does not permit
     * raw identifiers in the cache namespace.
     */
    public static function shouldHashKeys(bool $shouldHashKeys = true)
    {
        if (! $shouldHashKeys) {
            throw new InvalidArgumentException(
                'Disabling rate limiter key hashing is not permitted.'
            );
        }

        self::$shouldHashKeys = true;
    }
}
