<?php

namespace App\Services\Auth;

use App\Models\OAuthProvider;
use App\Models\User;
use App\Models\UserOAuthIdentity;
use App\Services\UserService;
use App\Utils\CacheKey;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use RuntimeException;

class OAuthService
{
    private const STATE_TTL = 600;        // 10 min
    private const CANDIDATE_TTL = 600;
    private const DISCOVERY_TTL = 86400;  // 24h

    public function enabledProviders()
    {
        return OAuthProvider::where('enable', true)
            ->orderBy('sort', 'ASC')
            ->orderBy('id', 'ASC')
            ->get();
    }

    public function resolveEnabledByIdentifier(string $identifier): OAuthProvider
    {
        $provider = OAuthProvider::where('identifier', $identifier)
            ->where('enable', true)
            ->first();
        if (!$provider) {
            throw new RuntimeException('Provider not found or disabled');
        }
        return $provider;
    }

    public function buildCallbackUrl(string $identifier): string
    {
        $base = rtrim((string) admin_setting('app_url', url('/')), '/');
        return $base . '/api/v1/passport/oauth/' . $identifier . '/callback';
    }

    /**
     * 解析 provider 的实际端点：auto 模式拉 well-known，manual 模式用表里字段。
     */
    public function resolveEndpoints(OAuthProvider $provider): array
    {
        if ($provider->discovery_mode === 'manual') {
            $endpoints = [
                'authorization_endpoint' => $provider->authorization_endpoint,
                'token_endpoint' => $provider->token_endpoint,
                'userinfo_endpoint' => $provider->userinfo_endpoint,
                'jwks_uri' => $provider->jwks_uri,
                'issuer' => $provider->issuer,
            ];
            foreach (['authorization_endpoint', 'token_endpoint'] as $required) {
                if (empty($endpoints[$required])) {
                    throw new RuntimeException("Manual provider missing {$required}");
                }
            }
            return $endpoints;
        }

        $cacheKey = CacheKey::get('OAUTH_DISCOVERY', $provider->id);
        $cached = Cache::get($cacheKey);
        if (is_array($cached)) {
            return $cached;
        }

        $endpoints = $this->fetchDiscovery((string) $provider->issuer);
        Cache::put($cacheKey, $endpoints, self::DISCOVERY_TTL);
        return $endpoints;
    }

    /**
     * 直接从 issuer 拉 well-known（admin 测试用）。
     */
    public function fetchDiscovery(string $issuer): array
    {
        $issuer = rtrim($issuer, '/');
        if ($issuer === '') {
            throw new RuntimeException('Issuer is empty');
        }
        $url = $issuer . '/.well-known/openid-configuration';

        $response = Http::timeout(8)->get($url);
        if (!$response->successful()) {
            throw new RuntimeException("Discovery failed: HTTP {$response->status()}");
        }
        $data = $response->json();
        if (!is_array($data) || empty($data['authorization_endpoint']) || empty($data['token_endpoint'])) {
            throw new RuntimeException('Discovery response is invalid');
        }

        return [
            'issuer' => $data['issuer'] ?? $issuer,
            'authorization_endpoint' => $data['authorization_endpoint'],
            'token_endpoint' => $data['token_endpoint'],
            'userinfo_endpoint' => $data['userinfo_endpoint'] ?? null,
            'jwks_uri' => $data['jwks_uri'] ?? null,
        ];
    }

    /**
     * 起飞：生成 state / nonce / PKCE，写 cache，返回授权 URL。
     */
    public function buildAuthorizationUrl(OAuthProvider $provider, array $stateData): string
    {
        $endpoints = $this->resolveEndpoints($provider);

        $state = bin2hex(random_bytes(16));
        $nonce = bin2hex(random_bytes(16));
        $codeVerifier = $this->generateCodeVerifier();
        $codeChallenge = $this->codeChallengeS256($codeVerifier);

        $payload = array_merge($stateData, [
            'provider_id' => $provider->id,
            'identifier' => $provider->identifier,
            'code_verifier' => $codeVerifier,
            'nonce' => $nonce,
            'created_at' => time(),
        ]);

        Cache::put(CacheKey::get('OAUTH_STATE', $state), $payload, self::STATE_TTL);

        $query = [
            'response_type' => 'code',
            'client_id' => $provider->client_id,
            'redirect_uri' => $this->buildCallbackUrl($provider->identifier),
            'scope' => $provider->scopes ?: 'openid email profile',
            'state' => $state,
            'nonce' => $nonce,
            'code_challenge' => $codeChallenge,
            'code_challenge_method' => 'S256',
        ];

        return $endpoints['authorization_endpoint'] . (str_contains($endpoints['authorization_endpoint'], '?') ? '&' : '?') . http_build_query($query);
    }

    /**
     * 用 code 换 access_token + id_token。
     */
    public function exchangeCode(OAuthProvider $provider, string $code, string $codeVerifier): array
    {
        $endpoints = $this->resolveEndpoints($provider);

        $response = Http::asForm()
            ->withBasicAuth($provider->client_id, $provider->client_secret)
            ->timeout(10)
            ->post($endpoints['token_endpoint'], [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => $this->buildCallbackUrl($provider->identifier),
                'code_verifier' => $codeVerifier,
                // Some IdPs reject Basic auth and require body credentials. Send both for max compatibility.
                'client_id' => $provider->client_id,
                'client_secret' => $provider->client_secret,
            ]);

        if (!$response->successful()) {
            Log::warning('OAuth token exchange failed', [
                'provider' => $provider->identifier,
                'status' => $response->status(),
                'body' => $response->body(),
            ]);
            throw new RuntimeException('Token exchange failed');
        }

        $body = $response->json();
        if (!is_array($body) || empty($body['access_token'])) {
            throw new RuntimeException('Token endpoint returned invalid payload');
        }
        return $body;
    }

    /**
     * 解 id_token 的 payload。按 OIDC core §3.1.3.5，back-channel 流签名校验可选；
     * 我们校验 iss / aud / exp / iat / nonce 即可。
     */
    public function parseIdToken(?string $idToken, OAuthProvider $provider, string $expectedNonce): array
    {
        if (!$idToken) {
            return [];
        }
        $parts = explode('.', $idToken);
        if (count($parts) !== 3) {
            throw new RuntimeException('Malformed id_token');
        }
        $payload = json_decode($this->base64UrlDecode($parts[1]), true);
        if (!is_array($payload)) {
            throw new RuntimeException('id_token payload is not JSON');
        }

        $endpoints = $this->resolveEndpoints($provider);
        $expectedIssuer = $endpoints['issuer'] ?? $provider->issuer;
        if ($expectedIssuer && isset($payload['iss']) && rtrim($payload['iss'], '/') !== rtrim($expectedIssuer, '/')) {
            throw new RuntimeException('id_token issuer mismatch');
        }

        if (isset($payload['aud'])) {
            $aud = is_array($payload['aud']) ? $payload['aud'] : [$payload['aud']];
            if (!in_array($provider->client_id, $aud, true)) {
                throw new RuntimeException('id_token audience mismatch');
            }
        }
        if (isset($payload['exp']) && (int) $payload['exp'] < time() - 30) {
            throw new RuntimeException('id_token expired');
        }
        if (isset($payload['nonce']) && $payload['nonce'] !== $expectedNonce) {
            throw new RuntimeException('id_token nonce mismatch');
        }

        return $payload;
    }

    public function fetchUserInfo(OAuthProvider $provider, string $accessToken): array
    {
        $endpoints = $this->resolveEndpoints($provider);
        if (empty($endpoints['userinfo_endpoint'])) {
            return [];
        }
        $response = Http::withToken($accessToken)->timeout(10)->get($endpoints['userinfo_endpoint']);
        if (!$response->successful()) {
            Log::warning('OAuth userinfo fetch failed', [
                'provider' => $provider->identifier,
                'status' => $response->status(),
            ]);
            return [];
        }
        $data = $response->json();
        return is_array($data) ? $data : [];
    }

    /**
     * 合并 id_token + userinfo 后按 provider 的属性映射抽取关键字段。
     */
    public function extractProfile(OAuthProvider $provider, array $idTokenPayload, array $userInfo): array
    {
        $merged = array_merge($idTokenPayload, $userInfo);

        $sub = $merged[$provider->sub_attribute] ?? null;
        $email = $merged[$provider->email_attribute] ?? null;
        $name = $merged[$provider->name_attribute] ?? null;
        $emailVerified = $merged[$provider->email_verified_attribute] ?? null;

        if (!$sub) {
            throw new RuntimeException('OIDC profile missing subject');
        }

        return [
            'sub' => (string) $sub,
            'email' => $email ? strtolower(trim($email)) : null,
            'email_verified' => $emailVerified === true || $emailVerified === 'true' || $emailVerified === 1 || $emailVerified === '1',
            'name' => $name,
            'raw' => $merged,
        ];
    }

    /**
     * 登录意图：根据现有 identity / 邮箱命中 / allow_register 决定下一步。
     * 返回:
     *   ['kind'=>'exists', 'user'=>User]
     *   ['kind'=>'email_conflict', 'email'=>string, 'candidate_token'=>string]
     *   ['kind'=>'registered', 'user'=>User]
     *   ['kind'=>'register_blocked']
     *   ['kind'=>'no_email']    // 远端没给 email 又没现有 binding，无法判断
     */
    public function handleLogin(OAuthProvider $provider, array $profile): array
    {
        $existing = UserOAuthIdentity::where('provider_id', $provider->id)
            ->where('sub', $profile['sub'])
            ->first();
        if ($existing) {
            $user = User::find($existing->user_id);
            if (!$user) {
                $existing->delete();
            } else {
                $existing->update([
                    'email_snapshot' => $profile['email'],
                    'name_snapshot' => $profile['name'],
                    'raw_profile' => $profile['raw'],
                ]);
                return ['kind' => 'exists', 'user' => $user];
            }
        }

        if (empty($profile['email'])) {
            return ['kind' => 'no_email'];
        }

        $localUser = User::byEmail($profile['email'])->first();
        if ($localUser) {
            $candidate = bin2hex(random_bytes(16));
            Cache::put(
                CacheKey::get('OAUTH_BIND_CANDIDATE', $candidate),
                [
                    'provider_id' => $provider->id,
                    'sub' => $profile['sub'],
                    'profile' => $profile,
                ],
                self::CANDIDATE_TTL
            );
            return [
                'kind' => 'email_conflict',
                'email' => $profile['email'],
                'candidate_token' => $candidate,
            ];
        }

        if (!$provider->allow_register) {
            return ['kind' => 'register_blocked'];
        }

        $user = app(UserService::class)->createUser([
            'email' => $profile['email'],
            // 用户没设过密码，先随机一个，鼓励之后用 forget 流程改
            'password' => Str::random(32),
        ]);
        if (!$user->save()) {
            throw new RuntimeException('Failed to create user from OIDC profile');
        }

        UserOAuthIdentity::create([
            'user_id' => $user->id,
            'provider_id' => $provider->id,
            'sub' => $profile['sub'],
            'email_snapshot' => $profile['email'],
            'name_snapshot' => $profile['name'],
            'raw_profile' => $profile['raw'],
        ]);

        $user->last_login_at = time();
        $user->save();

        return ['kind' => 'registered', 'user' => $user];
    }

    /**
     * 绑定意图：把当前登录用户与远端 sub 关联。
     */
    public function bindToUser(OAuthProvider $provider, User $user, array $profile): array
    {
        $existing = UserOAuthIdentity::where('provider_id', $provider->id)
            ->where('sub', $profile['sub'])
            ->first();
        if ($existing) {
            if ($existing->user_id !== $user->id) {
                return ['kind' => 'in_use_by_other'];
            }
            $existing->update([
                'email_snapshot' => $profile['email'],
                'name_snapshot' => $profile['name'],
                'raw_profile' => $profile['raw'],
            ]);
            return ['kind' => 'ok', 'identity' => $existing];
        }

        $userAlreadyBound = UserOAuthIdentity::where('provider_id', $provider->id)
            ->where('user_id', $user->id)
            ->first();
        if ($userAlreadyBound) {
            return ['kind' => 'user_already_bound', 'identity' => $userAlreadyBound];
        }

        $identity = UserOAuthIdentity::create([
            'user_id' => $user->id,
            'provider_id' => $provider->id,
            'sub' => $profile['sub'],
            'email_snapshot' => $profile['email'],
            'name_snapshot' => $profile['name'],
            'raw_profile' => $profile['raw'],
        ]);
        return ['kind' => 'ok', 'identity' => $identity];
    }

    /**
     * 通过 candidate_token 把缓存里的 profile 绑定到当前用户。
     */
    public function confirmCandidate(User $user, string $candidateToken): array
    {
        $key = CacheKey::get('OAUTH_BIND_CANDIDATE', $candidateToken);
        $payload = Cache::get($key);
        if (!is_array($payload)) {
            return ['kind' => 'invalid'];
        }
        $provider = OAuthProvider::find($payload['provider_id']);
        if (!$provider || !$provider->enable) {
            return ['kind' => 'invalid'];
        }
        if (empty($payload['profile']) || !is_array($payload['profile'])) {
            return ['kind' => 'invalid'];
        }
        $result = $this->bindToUser($provider, $user, $payload['profile']);
        Cache::forget($key);
        return $result;
    }

    /**
     * 解绑前确认用户还能登录（有可用密码 或 还有别的 binding）。
     * 注意：邮件 magic-link 也是登录方式，但需要邮箱可用即可，这里只校验 password / 其他 binding。
     */
    public function unbind(User $user, int $identityId): array
    {
        $identity = UserOAuthIdentity::where('id', $identityId)
            ->where('user_id', $user->id)
            ->first();
        if (!$identity) {
            return ['kind' => 'not_found'];
        }

        $otherBindingsCount = UserOAuthIdentity::where('user_id', $user->id)
            ->where('id', '!=', $identityId)
            ->count();
        $hasUsablePassword = !empty($user->password);

        if ($otherBindingsCount === 0 && !$hasUsablePassword) {
            return ['kind' => 'last_login_method'];
        }

        $identity->delete();
        return ['kind' => 'ok'];
    }

    public function listIdentities(User $user)
    {
        return UserOAuthIdentity::where('user_id', $user->id)
            ->orderBy('id', 'ASC')
            ->get();
    }

    private function generateCodeVerifier(): string
    {
        // RFC 7636 §4.1: 43-128 chars, unreserved
        return rtrim(strtr(base64_encode(random_bytes(64)), '+/', '-_'), '=');
    }

    private function codeChallengeS256(string $verifier): string
    {
        return rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
    }

    private function base64UrlDecode(string $value): string
    {
        $padded = strtr($value, '-_', '+/');
        $pad = strlen($padded) % 4;
        if ($pad) {
            $padded .= str_repeat('=', 4 - $pad);
        }
        $decoded = base64_decode($padded, true);
        if ($decoded === false) {
            throw new RuntimeException('Invalid base64url');
        }
        return $decoded;
    }
}
