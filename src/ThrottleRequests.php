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
use RuntimeException;
use Stringable;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

use function Illuminate\Support\enum_value;

class ThrottleRequests
{
    use InteractsWithTime;

    /**
     * Limiter usado para resolução dos limitadores nomeados.
     */
    protected RateLimiter $limiter;

    /**
     * Redis é obrigatório para garantir aquisição atômica.
     */
    protected Redis $redis;

    /**
     * Estado obtido atomicamente no Redis.
     *
     * Nunca é exposto ao cliente.
     *
     * @var array<string, int>
     */
    protected array $decaysAt = [];

    /**
     * @var array<string, int>
     */
    protected array $remaining = [];

    /**
     * Mantém as chaves opacas mesmo em logs/telemetria/cache.
     */
    protected static bool $shouldHashKeys = true;

    /**
     * Limites defensivos contra chaves gigantes controladas pelo cliente.
     */
    private const MAX_IDENTIFIER_LENGTH = 256;
    private const MAX_PREFIX_LENGTH = 128;

    /**
     * Em falha da infraestrutura do throttle, não executar a aplicação.
     *
     * Retry curto para não transformar a falha do Redis em avalanche.
     */
    private const FAILURE_RETRY_AFTER = 1;

    public function __construct(RateLimiter $limiter, Redis $redis)
    {
        $this->limiter = $limiter;
        $this->redis = $redis;
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
     */
    public function handle(
        $request,
        Closure $next,
        $maxAttempts = 60,
        $decayMinutes = 1,
        $prefix = ''
    ) {
        if (
            is_string($maxAttempts) &&
            func_num_args() === 3 &&
            ! is_null($namedLimiter = $this->limiter->limiter($maxAttempts))
        ) {
            return $this->handleRequestUsingNamedLimiter(
                $request,
                $next,
                $maxAttempts,
                $namedLimiter
            );
        }

        $maxAttempts = $this->resolveMaxAttempts($request, $maxAttempts);
        $decaySeconds = $this->normalizeDecaySeconds($decayMinutes);
        $prefix = $this->normalizePrefix($prefix);

        return $this->handleRequest(
            $request,
            $next,
            [
                (object) [
                    'key' => $this->formatIdentifier(
                        $prefix.'|'.$this->resolveRequestSignature($request)
                    ),
                    'maxAttempts' => $maxAttempts,
                    'decaySeconds' => $decaySeconds,

                    /*
                     * Segurança de disponibilidade:
                     *
                     * a capacidade é SEMPRE reservada antes de $next().
                     * afterCallback não pode postergar a contabilização.
                     */
                    'afterCallback' => null,

                    'responseCallback' => null,
                ],
            ]
        );
    }

    /**
     * Handle a named limiter.
     */
    protected function handleRequestUsingNamedLimiter(
        $request,
        Closure $next,
        $limiterName,
        Closure $limiter
    ) {
        try {
            $limiterResponse = $limiter($request);
        } catch (Throwable $e) {
            /*
             * O resolver do limiter falhou.
             *
             * Fail-closed: não deixa a requisição atingir controller,
             * banco, filas, APIs externas etc.
             */
            throw $this->buildInfrastructureFailureException();
        }

        if ($limiterResponse instanceof Response) {
            return $limiterResponse;
        }

        if ($limiterResponse instanceof Unlimited) {
            /*
             * Unlimited é uma decisão explícita da configuração.
             */
            return $next($request);
        }

        $limits = Collection::wrap($limiterResponse)
            ->map(function ($limit) use ($limiterName) {
                $maxAttempts = $this->normalizeMaxAttempts(
                    $limit->maxAttempts ?? null
                );

                $decaySeconds = $this->normalizeDecaySecondsValue(
                    $limit->decaySeconds ?? null
                );

                $rawKey = $this->normalizeIdentifier(
                    $limiterName,
                    'limiter'
                ).'|'.$this->normalizeIdentifier(
                    $limit->key ?? '',
                    'limit key'
                );

                return (object) [
                    /*
                     * SHA-256 em vez de MD5/SHA-1.
                     */
                    'key' => $this->formatIdentifier($rawKey),

                    'maxAttempts' => $maxAttempts,
                    'decaySeconds' => $decaySeconds,

                    /*
                     * afterCallback é intencionalmente ignorado nesta
                     * variante security-first.
                     *
                     * Esperar a resposta para consumir a tentativa permite
                     * que N requisições caras entrem simultaneamente.
                     */
                    'afterCallback' => null,

                    'responseCallback' =>
                        $limit->responseCallback ?? null,
                ];
            })
            ->all();

        if ($limits === []) {
            /*
             * Configuração ambígua/incorreta não deve resultar em bypass.
             */
            throw $this->buildInfrastructureFailureException();
        }

        return $this->handleRequest(
            $request,
            $next,
            $limits
        );
    }

    /**
     * Faz a reserva de TODOS os limites antes de executar a aplicação.
     *
     * Propriedade fundamental:
     *
     *      acquire(key)
     *
     * substitui:
     *
     *      tooManyAttempts(key)
     *      hit(key)
     *
     * porque a primeira forma é uma única operação atômica no Redis.
     */
    protected function handleRequest(
        $request,
        Closure $next,
        array $limits
    ) {
        /*
         * PRIMEIRA FASE:
         *
         * nenhuma lógica da aplicação é executada antes que todos os
         * limitadores tenham sido avaliados/reservados.
         */
        foreach ($limits as $limit) {
            $allowed = $this->reserveAttemptAtomically(
                $limit->key,
                $limit->maxAttempts,
                $limit->decaySeconds
            );

            if (! $allowed) {
                throw $this->buildException(
                    $request,
                    $limit->key,
                    $limit->maxAttempts,
                    $limit->responseCallback
                );
            }
        }

        /*
         * Somente chegamos aqui se a capacidade foi adquirida.
         *
         * CPU / controller / DB / filas / integrações ficam protegidos
         * do excesso detectado pelo limiter.
         */
        $response = $next($request);

        /*
         * Headers não fazem novas consultas ao contador.
         *
         * Utilizamos o estado retornado pela MESMA operação atômica que
         * autorizou a requisição.
         */
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

    /**
     * Operação crítica atomicamente consistente.
     */
    protected function reserveAttemptAtomically(
        string $key,
        int $maxAttempts,
        int $decaySeconds
    ): bool {
        try {
            $limiter = new DurationLimiter(
                $this->redis->connection(),
                $key,
                $maxAttempts,
                $decaySeconds
            );

            /*
             * acquire() executa a decisão e o incremento em uma única
             * execução Lua no Redis.
             */
            $allowed = $limiter->acquire();

            $this->decaysAt[$key] = max(
                $this->currentTime(),
                (int) $limiter->decaysAt
            );

            $this->remaining[$key] = max(
                0,
                (int) $limiter->remaining
            );

            return $allowed;
        } catch (Throwable $e) {
            /*
             * FAIL-CLOSED.
             *
             * Não fazer fallback para:
             *
             *   return true;
             *   $next($request);
             *
             * nem para um limiter local por processo.
             *
             * Esses fallbacks permitem bypass exatamente quando a camada
             * de proteção está indisponível.
             */
            throw $this->buildInfrastructureFailureException();
        }
    }

    /**
     * Resolve max attempts.
     */
    protected function resolveMaxAttempts(
        $request,
        $maxAttempts
    ): int {
        if (
            is_string($maxAttempts) &&
            str_contains($maxAttempts, '|')
        ) {
            $parts = explode('|', $maxAttempts, 2);

            $maxAttempts = $parts[
                $request->user() ? 1 : 0
            ];
        }

        if (
            ! is_numeric($maxAttempts) &&
            $request->user()?->hasAttribute($maxAttempts)
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
     * Assinatura robusta da requisição.
     *
     * Não aceita IP inválido, vazio ou identificadores arbitrariamente
     * grandes.
     */
    protected function resolveRequestSignature($request): string
    {
        $ip = $this->resolveCanonicalIp($request);

        /*
         * Não utilizamos Host/X-Forwarded-Host diretamente na assinatura.
         *
         * O escopo é obtido da definição interna da rota.
         */
        $route = $request->route();

        if (! $route) {
            throw new RuntimeException(
                'Rate-limit signature unavailable.'
            );
        }

        $routeIdentity = $route->getName();

        if (! is_string($routeIdentity) || $routeIdentity === '') {
            $routeIdentity = $request->method().'|'.$route->uri();
        }

        $routeIdentity = $this->normalizeIdentifier(
            $routeIdentity,
            'route'
        );

        if ($user = $request->user()) {
            $userId = $this->normalizeIdentifier(
                $user->getAuthIdentifier(),
                'authenticated principal'
            );

            /*
             * Combina principal + IP.
             *
             * Isso impede que a representação textual arbitrária de um
             * identificador ou IP produza buckets diferentes.
             */
            $material =
                'v2|auth|'.
                $routeIdentity.'|'.
                $userId.'|'.
                $ip;
        } else {
            $material =
                'v2|guest|'.
                $routeIdentity.'|'.
                $ip;
        }

        return $this->formatIdentifier($material);
    }

    /**
     * Obtém e canonicaliza o endereço IP.
     */
    private function resolveCanonicalIp($request): string
    {
        /*
         * getClientIp()/ip() somente deve considerar Forwarded /
         * X-Forwarded-For quando Trusted Proxies estiver corretamente
         * configurado.
         */
        $ip = $request->getClientIp();

        if (
            ! is_string($ip) ||
            filter_var($ip, FILTER_VALIDATE_IP) === false
        ) {
            throw new RuntimeException(
                'Rate-limit identity unavailable.'
            );
        }

        $binary = @inet_pton($ip);

        if ($binary === false) {
            throw new RuntimeException(
                'Rate-limit identity unavailable.'
            );
        }

        /*
         * inet_pton elimina diferenças textuais equivalentes de IPv6,
         * como compressões diferentes do mesmo endereço.
         */
        return bin2hex($binary);
    }

    /**
     * Validação estrita de identificadores.
     */
    private function normalizeIdentifier(
        mixed $value,
        string $type
    ): string {
        if (
            ! is_string($value) &&
            ! is_int($value) &&
            ! $value instanceof Stringable
        ) {
            throw new RuntimeException(
                'Rate-limit identity unavailable.'
            );
        }

        $value = trim((string) $value);

        if (
            $value === '' ||
            strlen($value) > self::MAX_IDENTIFIER_LENGTH
        ) {
            throw new RuntimeException(
                'Rate-limit identity unavailable.'
            );
        }

        /*
         * Caracteres de controle não são permitidos.
         */
        if (preg_match('/[\x00-\x1F\x7F]/', $value)) {
            throw new RuntimeException(
                'Rate-limit identity unavailable.'
            );
        }

        return $type.':'.$value;
    }

    /**
     * Cria resposta 429.
     */
    protected function buildException(
        $request,
        $key,
        $maxAttempts,
        $responseCallback = null
    ) {
        /*
         * Nunca devolve Retry-After negativo ou zero.
         */
        $retryAfter = max(
            1,
            $this->getTimeUntilNextRetry($key)
        );

        $headers = $this->getHeaders(
            $maxAttempts,
            0,
            $retryAfter
        );

        if (is_callable($responseCallback)) {
            /*
             * Callback continua possível para compatibilidade.
             *
             * Nenhum detalhe interno do limiter é passado ao callback:
             * somente request + headers públicos.
             */
            try {
                $response = $responseCallback(
                    $request,
                    $headers
                );

                if ($response instanceof Response) {
                    return new HttpResponseException($response);
                }
            } catch (Throwable $e) {
                /*
                 * Callback customizado não deve transformar o throttle em
                 * bypass nem vazar a exceção interna.
                 */
            }
        }

        return new ThrottleRequestsException(
            'Too Many Requests.',
            null,
            $headers
        );
    }

    /**
     * Falha da infraestrutura do limiter.
     *
     * Não informa Redis, host, driver, chave, conexão ou exceção.
     */
    protected function buildInfrastructureFailureException():
        HttpResponseException
    {
        $retryAfter = self::FAILURE_RETRY_AFTER;

        return new HttpResponseException(
            new Response(
                '',
                Response::HTTP_SERVICE_UNAVAILABLE,
                [
                    'Retry-After' => (string) $retryAfter,
                    'Cache-Control' => 'no-store',
                ]
            )
        );
    }

    /**
     * Tempo restante do bucket obtido da operação atômica.
     */
    protected function getTimeUntilNextRetry(
        string $key
    ): int {
        $decaysAt = $this->decaysAt[$key] ?? null;

        if (! is_int($decaysAt)) {
            /*
             * Estado inesperado => comportamento conservador.
             */
            return self::FAILURE_RETRY_AFTER;
        }

        return max(
            1,
            $decaysAt - $this->currentTime()
        );
    }

    /**
     * Adiciona headers sem substituir um limite mais restritivo já
     * presente na resposta.
     */
    protected function addHeaders(
        Response $response,
        $maxAttempts,
        $remainingAttempts,
        $retryAfter = null
    ): Response {
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

    /**
     * Gera somente metadados públicos.
     */
    protected function getHeaders(
        $maxAttempts,
        $remainingAttempts,
        $retryAfter = null,
        ?Response $response = null
    ): array {
        $maxAttempts = max(1, (int) $maxAttempts);
        $remainingAttempts = max(
            0,
            min(
                $maxAttempts,
                (int) $remainingAttempts
            )
        );

        if ($response) {
            $existingRemaining =
                $response->headers->get(
                    'X-RateLimit-Remaining'
                );

            if (
                $existingRemaining !== null &&
                (int) $existingRemaining <= $remainingAttempts
            ) {
                return [];
            }
        }

        $headers = [
            'X-RateLimit-Limit' =>
                (string) $maxAttempts,

            'X-RateLimit-Remaining' =>
                (string) $remainingAttempts,
        ];

        if ($retryAfter !== null) {
            $retryAfter = max(1, (int) $retryAfter);

            $headers['Retry-After'] =
                (string) $retryAfter;

            /*
             * Timestamp público de reset; nenhuma informação sobre
             * backend/cache.
             */
            $headers['X-RateLimit-Reset'] =
                (string) $this->availableAt($retryAfter);
        }

        return $headers;
    }

    /**
     * Saldo vem da mesma aquisição atômica.
     *
     * Não fazemos uma leitura separada retriesLeft(), pois outra
     * requisição poderia alterar o valor imediatamente depois.
     */
    protected function calculateRemainingAttempts(
        string $key,
        int $maxAttempts,
        $retryAfter = null
    ): int {
        if ($retryAfter !== null) {
            return 0;
        }

        return max(
            0,
            min(
                $maxAttempts,
                $this->remaining[$key] ?? 0
            )
        );
    }

    private function normalizeMaxAttempts(
        mixed $maxAttempts
    ): int {
        if (
            filter_var(
                $maxAttempts,
                FILTER_VALIDATE_INT
            ) === false
        ) {
            throw new RuntimeException(
                'Invalid rate-limit configuration.'
            );
        }

        $maxAttempts = (int) $maxAttempts;

        if ($maxAttempts < 1) {
            throw new RuntimeException(
                'Invalid rate-limit configuration.'
            );
        }

        return $maxAttempts;
    }

    /**
     * Entrada em minutos usada pelo middleware tradicional.
     */
    private function normalizeDecaySeconds(
        mixed $decayMinutes
    ): int {
        if (
            ! is_numeric($decayMinutes) ||
            ! is_finite((float) $decayMinutes)
        ) {
            throw new RuntimeException(
                'Invalid rate-limit configuration.'
            );
        }

        $seconds = (int) ceil(
            (float) $decayMinutes * 60
        );

        if ($seconds < 1) {
            throw new RuntimeException(
                'Invalid rate-limit configuration.'
            );
        }

        return $seconds;
    }

    /**
     * Entrada de Limit::decaySeconds.
     */
    private function normalizeDecaySecondsValue(
        mixed $seconds
    ): int {
        if (
            ! is_numeric($seconds) ||
            ! is_finite((float) $seconds)
        ) {
            throw new RuntimeException(
                'Invalid rate-limit configuration.'
            );
        }

        $seconds = (int) ceil((float) $seconds);

        if ($seconds < 1) {
            throw new RuntimeException(
                'Invalid rate-limit configuration.'
            );
        }

        return $seconds;
    }

    private function normalizePrefix(
        mixed $prefix
    ): string {
        if (! is_string($prefix)) {
            throw new RuntimeException(
                'Invalid rate-limit configuration.'
            );
        }

        if (strlen($prefix) > self::MAX_PREFIX_LENGTH) {
            throw new RuntimeException(
                'Invalid rate-limit configuration.'
            );
        }

        return $prefix;
    }

    /**
     * Chave opaca.
     */
    private function formatIdentifier(
        string $value
    ): string {
        /*
         * Mesmo quando shouldHashKeys(false) for usado, entradas já
         * passaram por validação/normalização.
         *
         * Para produção security-first, mantenha hashing habilitado.
         */
        return self::$shouldHashKeys
            ? hash('sha256', $value)
            : $value;
    }

    public static function shouldHashKeys(
        bool $shouldHashKeys = true
    ): void {
        self::$shouldHashKeys = $shouldHashKeys;
    }
}
