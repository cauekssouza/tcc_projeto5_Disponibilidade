<?php

declare(strict_types=1);

namespace Illuminate\Routing\Middleware;

use Closure;
use Illuminate\Cache\RateLimiter;
use Illuminate\Cache\RateLimiting\Unlimited;
use Illuminate\Http\Exceptions\HttpResponseException;
use Illuminate\Http\Exceptions\ThrottleRequestsException;
use Illuminate\Http\Request;
use Illuminate\Routing\Exceptions\MissingRateLimiterException;
use Illuminate\Support\Collection;
use Illuminate\Support\InteractsWithTime;
use RuntimeException;
use Symfony\Component\HttpFoundation\Response;
use UnitEnum;

use function Illuminate\Support\enum_value;

class ThrottleRequests
{
    use InteractsWithTime;

    protected static bool $shouldHashKeys = true;

    public function __construct(
        protected RateLimiter $limiter,
    ) {
    }

    public static function using(UnitEnum|string $name): string
    {
        return static::class . ':' . enum_value($name);
    }

    /**
     * @named-arguments-supported
     */
    public static function with(
        int $maxAttempts = 60,
        int $decayMinutes = 1,
        string $prefix = '',
    ): string {
        return sprintf(
            '%s:%d,%d,%s',
            static::class,
            $maxAttempts,
            $decayMinutes,
            $prefix,
        );
    }

    /**
     * @throws ThrottleRequestsException
     * @throws MissingRateLimiterException
     */
    public function handle(
        Request $request,
        Closure $next,
        int|string $maxAttempts = 60,
        float|int $decayMinutes = 1,
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

        return $this->handleRequest(
            $request,
            $next,
            [
                (object) [
                    'key' => $prefix . $this->resolveRequestSignature($request),
                    'maxAttempts' => $this->resolveMaxAttempts($request, $maxAttempts),
                    'decaySeconds' => 60 * $decayMinutes,
                    'afterCallback' => null,
                    'responseCallback' => null,
                ],
            ],
        );
    }

    /**
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

        $limits = Collection::wrap($limiterResponse)
            ->map(
                fn ($limit): object => (object) [
                    'key' => static::$shouldHashKeys
                        ? md5($limiterName . $limit->key)
                        : $limiterName . ':' . $limit->key,
                    'maxAttempts' => $limit->maxAttempts,
                    'decaySeconds' => $limit->decaySeconds,
                    'afterCallback' => $limit->afterCallback,
                    'responseCallback' => $limit->responseCallback,
                ],
            )
            ->all();

        return $this->handleRequest($request, $next, $limits);
    }

    /**
     * @param array<int, object> $limits
     *
     * @throws ThrottleRequestsException
     */
    protected function handleRequest(
        Request $request,
        Closure $next,
        array $limits,
    ): Response {
        foreach ($limits as $limit) {
            if (! $this->limiter->tooManyAttempts(
                $limit->key,
                $limit->maxAttempts,
            )) {
                continue;
            }

            throw $this->buildException(
                $request,
                $limit->key,
                $limit->maxAttempts,
                $limit->responseCallback,
            );
        }

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
     * @throws MissingRateLimiterException
     */
    protected function resolveMaxAttempts(
        Request $request,
        int|string $maxAttempts,
    ): int {
        $user = $request->user();

        if (
            is_string($maxAttempts)
            && str_contains($maxAttempts, '|')
        ) {
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

        throw $user === null
            ? MissingRateLimiterException::forLimiter($maxAttempts)
            : MissingRateLimiterException::forLimiterAndUser(
                $maxAttempts,
                $user::class,
            );
    }

    /**
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
                $route->getDomain() . '|' . $request->ip(),
            );
        }

        throw new RuntimeException(
            'Unable to generate the request signature. Route unavailable.',
        );
    }

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

        if ($responseCallback !== null) {
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

    protected function getTimeUntilNextRetry(string $key): int
    {
        return $this->limiter->availableIn($key);
    }

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

    protected function calculateRemainingAttempts(
        string $key,
        int $maxAttempts,
        ?int $retryAfter = null,
    ): int {
        return $retryAfter === null
            ? $this->limiter->retriesLeft($key, $maxAttempts)
            : 0;
    }

    private function formatIdentifier(string $value): string
    {
        return static::$shouldHashKeys
            ? sha1($value)
            : $value;
    }

    public static function shouldHashKeys(
        bool $shouldHashKeys = true,
    ): void {
        static::$shouldHashKeys = $shouldHashKeys;
    }
}
