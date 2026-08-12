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

    protected RateLimiter $limiter;

    protected static bool $shouldHashKeys = true;

    public function __construct(RateLimiter $limiter)
    {
        $this->limiter = $limiter;
    }

    public static function using($name): string
    {
        return static::class.':'.enum_value($name);
    }

    /**
     * @named-arguments-supported
     */
    public static function with(
        $maxAttempts = 60,
        $decayMinutes = 1,
        $prefix = ''
    ): string {
        return static::class.':'.implode(',', func_get_args());
    }

    public function handle(
        $request,
        Closure $next,
        $maxAttempts = 60,
        $decayMinutes = 1,
        $prefix = ''
    ) {
        $namedLimiter = $this->resolveNamedLimiter($maxAttempts);

        if ($namedLimiter !== null && func_num_args() === 3) {
            return $this->handleNamedLimiter(
                $request,
                $next,
                $maxAttempts,
                $namedLimiter
            );
        }

        $limit = (object) [
            'key' => $prefix.$this->resolveRequestSignature($request),
            'maxAttempts' => $this->resolveMaxAttempts($request, $maxAttempts),
            'decaySeconds' => max(1, (int) round(60 * $decayMinutes)),
            'afterCallback' => null,
            'responseCallback' => null,
        ];

        return $this->handleRequest($request, $next, [$limit]);
    }

    protected function resolveNamedLimiter($maxAttempts): ?Closure
    {
        if (! is_string($maxAttempts)) {
            return null;
        }

        return $this->limiter->limiter($maxAttempts);
    }

    protected function handleNamedLimiter(
        $request,
        Closure $next,
        string $limiterName,
        Closure $limiter
    ) {
        $result = $limiter($request);

        if ($result instanceof Response) {
            return $result;
        }

        if ($result instanceof Unlimited) {
            return $next($request);
        }

        $limits = [];

        foreach ((array) $this->wrapLimiterResponse($result) as $limit) {
            $limits[] = (object) [
                'key' => $this->buildNamedLimiterKey(
                    $limiterName,
                    $limit->key
                ),
                'maxAttempts' => $limit->maxAttempts,
                'decaySeconds' => $limit->decaySeconds,
                'afterCallback' => $limit->afterCallback,
                'responseCallback' => $limit->responseCallback,
            ];
        }

        return $this->handleRequest($request, $next, $limits);
    }

    /**
     * Normaliza o retorno do named limiter sem precisar criar
     * uma Collection em toda requisição.
     */
    protected function wrapLimiterResponse($response): array
    {
        return is_array($response)
            ? $response
            : [$response];
    }

    protected function buildNamedLimiterKey(
        string $limiterName,
        $key
    ): string {
        $value = $limiterName.$key;

        return static::$shouldHashKeys
            ? md5($value)
            : $limiterName.':'.$key;
    }

    protected function handleRequest(
        $request,
        Closure $next,
        array $limits
    ): Response {
        $this->assertWithinLimits($request, $limits);

        $this->registerImmediateHits($limits);

        $response = $next($request);

        $this->registerConditionalHits($limits, $response);

        return $this->addLimitHeaders($response, $limits);
    }

    /**
     * Verifica todos os limites antes de executar a aplicação.
     *
     * Isso evita executar controller / banco / APIs externas quando
     * a requisição já deveria ser rejeitada.
     */
    protected function assertWithinLimits($request, array $limits): void
    {
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
     * Consome imediatamente limites sem callback condicional.
     */
    protected function registerImmediateHits(array $limits): void
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
     * Consome limites cuja contabilização depende da resposta.
     */
    protected function registerConditionalHits(
        array $limits,
        Response $response
    ): void {
        foreach ($limits as $limit) {
            if ($limit->afterCallback === null) {
                continue;
            }

            if (($limit->afterCallback)($response)) {
                $this->limiter->hit(
                    $limit->key,
                    $limit->decaySeconds
                );
            }
        }
    }

    protected function addLimitHeaders(
        Response $response,
        array $limits
    ): Response {
        foreach ($limits as $limit) {
            $response = $this->addHeaders(
                $response,
                $limit->maxAttempts,
                $this->calculateRemainingAttempts(
                    $limit->key,
                    $limit->maxAttempts
                )
            );
        }

        return $response;
    }

    protected function resolveMaxAttempts($request, $maxAttempts): int
    {
        $user = $request->user();

        if (
            is_string($maxAttempts) &&
            str_contains($maxAttempts, '|')
        ) {
            [$guestLimit, $authenticatedLimit] = explode(
                '|',
                $maxAttempts,
                2
            );

            $maxAttempts = $user
                ? $authenticatedLimit
                : $guestLimit;
        }

        if (
            ! is_numeric($maxAttempts) &&
            $user?->hasAttribute($maxAttempts)
        ) {
            $maxAttempts = $user->{$maxAttempts};
        }

        if (is_numeric($maxAttempts)) {
            return max(0, (int) $maxAttempts);
        }

        if ($user === null) {
            throw MissingRateLimiterException::forLimiter(
                $maxAttempts
            );
        }

        throw MissingRateLimiterException::forLimiterAndUser(
            $maxAttempts,
            get_class($user)
        );
    }

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
                $route->getDomain().'|'.$request->ip()
            );
        }

        throw new RuntimeException(
            'Unable to generate the request signature. Route unavailable.'
        );
    }

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

    protected function getTimeUntilNextRetry(string $key): int
    {
        return $this->limiter->availableIn($key);
    }

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

    protected function getHeaders(
        int $maxAttempts,
        int $remainingAttempts,
        ?int $retryAfter = null,
        ?Response $response = null
    ): array {
        if (
            $response !== null &&
            $response->headers->has('X-RateLimit-Remaining') &&
            (int) $response->headers->get('X-RateLimit-Remaining')
                <= $remainingAttempts
        ) {
            return [];
        }

        $headers = [
            'X-RateLimit-Limit' => $maxAttempts,
            'X-RateLimit-Remaining' => max(0, $remainingAttempts),
        ];

        if ($retryAfter !== null) {
            $headers['Retry-After'] = $retryAfter;
            $headers['X-RateLimit-Reset'] =
                $this->availableAt($retryAfter);
        }

        return $headers;
    }

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

    private function formatIdentifier(string $value): string
    {
        return static::$shouldHashKeys
            ? sha1($value)
            : $value;
    }

    public static function shouldHashKeys(
        bool $shouldHashKeys = true
    ): void {
        static::$shouldHashKeys = $shouldHashKeys;
    }
}
