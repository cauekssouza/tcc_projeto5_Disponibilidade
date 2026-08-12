<?php

namespace Illuminate\Routing\Middleware;

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

use function Illuminate\Support\enum_value;

class ThrottleRequests
{
    use InteractsWithTime;

    /**
     * The rate limiter instance.
     *
     * @var \Illuminate\Cache\RateLimiter
     */
    protected $limiter;

    /**
     * Indicates if rate limiter keys should be hashed.
     *
     * @var bool
     */
    protected static $shouldHashKeys = true;

    /**
     * Create a new request throttler.
     *
     * @param  \Illuminate\Cache\RateLimiter  $limiter
     */
    public function __construct(RateLimiter $limiter)
    {
        $this->limiter = $limiter;
    }

    /**
     * Specify the named rate limiter to use for the middleware.
     *
     * @param  \UnitEnum|string  $name
     * @return string
     */
    public static function using($name)
    {
        return static::class.':'.enum_value($name);
    }

    /**
     * Specify the rate limiter configuration for the middleware.
     *
     * @param  int  $maxAttempts
     * @param  int|float  $decayMinutes
     * @param  string  $prefix
     * @return string
     *
     * @named-arguments-supported
     */
    public static function with(
        $maxAttempts = 60,
        $decayMinutes = 1,
        $prefix = ''
    ) {
        return static::class.':'.implode(',', func_get_args());
    }

    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @param  int|string  $maxAttempts
     * @param  int|float  $decayMinutes
     * @param  string  $prefix
     * @return \Symfony\Component\HttpFoundation\Response
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
        if (is_string($maxAttempts) && func_num_args() === 3) {
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
     * Handle an incoming request using a named limiter.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @param  string  $limiterName
     * @param  \Closure  $limiter
     * @return \Symfony\Component\HttpFoundation\Response
     *
     * @throws \Illuminate\Http\Exceptions\ThrottleRequestsException
     */
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
                    'key' => $this->formatNamedLimiterKey(
                        $limiterName,
                        $limit->key
                    ),
                    'maxAttempts' => $limit->maxAttempts,
                    'decaySeconds' => $limit->decaySeconds,
                    'afterCallback' => $limit->afterCallback,
                    'responseCallback' => $limit->responseCallback,
                ];
            })
            ->all();

        return $this->handleRequest($request, $next, $limits);
    }

    /**
     * Handle the configured rate limits.
     *
     * Important:
     * All limits are checked before consuming any attempt.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @param  array  $limits
     * @return \Symfony\Component\HttpFoundation\Response
     *
     * @throws \Illuminate\Http\Exceptions\ThrottleRequestsException
     */
    protected function handleRequest($request, Closure $next, array $limits)
    {
        /*
         * Phase 1: validate every limit before modifying counters.
         *
         * Keeping this as a separate pass is intentional. If checking and
         * incrementing were combined, an earlier limit could be consumed
         * even when a later limit rejects the same request.
         */
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

        /*
         * Phase 2: consume attempts that are counted before the response.
         */
        foreach ($limits as $limit) {
            if ($limit->afterCallback !== null) {
                continue;
            }

            $this->limiter->hit(
                $limit->key,
                $limit->decaySeconds
            );
        }

        $response = $next($request);

        /*
         * Phase 3: process conditional limits and response headers.
         */
        foreach ($limits as $limit) {
            $afterCallback = $limit->afterCallback;

            if ($afterCallback !== null && $afterCallback($response)) {
                $this->limiter->hit(
                    $limit->key,
                    $limit->decaySeconds
                );
            }

            $remainingAttempts = $this->calculateRemainingAttempts(
                $limit->key,
                $limit->maxAttempts
            );

            $this->addHeaders(
                $response,
                $limit->maxAttempts,
                $remainingAttempts
            );
        }

        return $response;
    }

    /**
     * Resolve the maximum number of attempts.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  int|string  $maxAttempts
     * @return int
     *
     * @throws \Illuminate\Routing\Exceptions\MissingRateLimiterException
     */
    protected function resolveMaxAttempts($request, $maxAttempts)
    {
        /*
         * Resolve the authenticated user once. Depending on the authentication
         * guard, repeatedly calling user() may involve unnecessary work.
         */
        $user = $request->user();

        if (is_string($maxAttempts) && str_contains($maxAttempts, '|')) {
            [$guestAttempts, $authenticatedAttempts] = explode(
                '|',
                $maxAttempts,
                2
            );

            $maxAttempts = $user
                ? $authenticatedAttempts
                : $guestAttempts;
        }

        if (
            ! is_numeric($maxAttempts) &&
            $user !== null &&
            $user->hasAttribute($maxAttempts)
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
            get_class($user)
        );
    }

    /**
     * Resolve the request signature.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return string
     *
     * @throws \RuntimeException
     */
    protected function resolveRequestSignature($request)
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
                $route->getDomain().'|'.$request->ip()
            );
        }

        throw new RuntimeException(
            'Unable to generate the request signature. Route unavailable.'
        );
    }

    /**
     * Create a "too many attempts" exception.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $key
     * @param  int  $maxAttempts
     * @param  callable|null  $responseCallback
     * @return \Illuminate\Http\Exceptions\ThrottleRequestsException|\Illuminate\Http\Exceptions\HttpResponseException
     */
    protected function buildException(
        $request,
        $key,
        $maxAttempts,
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
     *
     * @param  string  $key
     * @return int
     */
    protected function getTimeUntilNextRetry($key)
    {
        return $this->limiter->availableIn($key);
    }

    /**
     * Add rate-limit headers to the response.
     *
     * @param  \Symfony\Component\HttpFoundation\Response  $response
     * @param  int  $maxAttempts
     * @param  int  $remainingAttempts
     * @param  int|null  $retryAfter
     * @return \Symfony\Component\HttpFoundation\Response
     */
    protected function addHeaders(
        Response $response,
        $maxAttempts,
        $remainingAttempts,
        $retryAfter = null
    ) {
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
     * Get rate-limit header information.
     *
     * @param  int  $maxAttempts
     * @param  int  $remainingAttempts
     * @param  int|null  $retryAfter
     * @param  \Symfony\Component\HttpFoundation\Response|null  $response
     * @return array
     */
    protected function getHeaders(
        $maxAttempts,
        $remainingAttempts,
        $retryAfter = null,
        ?Response $response = null
    ) {
        if ($response !== null) {
            $currentRemaining = $response->headers->get(
                'X-RateLimit-Remaining'
            );

            /*
             * Preserve the most restrictive limit when multiple limiters
             * contribute headers to the same response.
             */
            if (
                $currentRemaining !== null &&
                (int) $currentRemaining <= (int) $remainingAttempts
            ) {
                return [];
            }
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
     *
     * @param  string  $key
     * @param  int  $maxAttempts
     * @param  int|null  $retryAfter
     * @return int
     */
    protected function calculateRemainingAttempts(
        $key,
        $maxAttempts,
        $retryAfter = null
    ) {
        if ($retryAfter !== null) {
            return 0;
        }

        return $this->limiter->retriesLeft(
            $key,
            $maxAttempts
        );
    }

    /**
     * Format a named limiter key.
     *
     * @param  string  $limiterName
     * @param  string  $key
     * @return string
     */
    private function formatNamedLimiterKey($limiterName, $key)
    {
        $value = $limiterName.$key;

        return self::$shouldHashKeys
            ? md5($value)
            : $limiterName.':'.$key;
    }

    /**
     * Format an identifier according to the hashing configuration.
     *
     * @param  string  $value
     * @return string
     */
    private function formatIdentifier($value)
    {
        return self::$shouldHashKeys
            ? sha1($value)
            : $value;
    }

    /**
     * Specify whether rate limiter keys should be hashed.
     *
     * @param  bool  $shouldHashKeys
     * @return void
     */
    public static function shouldHashKeys(bool $shouldHashKeys = true)
    {
        self::$shouldHashKeys = $shouldHashKeys;
    }
}
