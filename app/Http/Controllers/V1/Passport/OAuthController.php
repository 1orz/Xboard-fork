<?php

namespace App\Http\Controllers\V1\Passport;

use App\Http\Controllers\Controller;
use App\Models\OAuthProvider;
use App\Services\Auth\OAuthService;
use App\Services\AuthService;
use App\Utils\CacheKey;
use App\Utils\Helper;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Throwable;

class OAuthController extends Controller
{
    public function __construct(private OAuthService $service)
    {
    }

    /**
     * 公开列表，前端 Login 页和 Profile 页都用。
     */
    public function index()
    {
        $providers = $this->service->enabledProviders()->map(function (OAuthProvider $p) {
            return [
                'identifier' => $p->identifier,
                'name' => $p->name,
                'icon' => $p->icon,
                'allow_bind' => (bool) $p->allow_bind,
            ];
        })->values();

        return $this->success($providers);
    }

    /**
     * GET /api/v1/passport/oauth/{identifier}/redirect
     */
    public function redirect(Request $request, string $identifier): RedirectResponse
    {
        try {
            $provider = $this->service->resolveEnabledByIdentifier($identifier);
        } catch (Throwable $e) {
            return $this->redirectToFrontend(['oauth_error' => 'provider_not_found']);
        }

        $intent = $request->input('intent', 'login') === 'bind' ? 'bind' : 'login';
        $redirect = (string) $request->input('redirect', $intent === 'bind' ? 'profile' : 'dashboard');

        $stateData = [
            'intent' => $intent,
            'redirect' => $redirect,
            'ip' => $request->ip(),
        ];

        if ($intent === 'bind') {
            if (!$provider->allow_bind) {
                return $this->redirectToFrontend([
                    'oauth_error' => 'bind_disabled',
                ], $redirect);
            }
            $bindToken = (string) $request->input('bind_token');
            $user = $bindToken ? AuthService::findUserByBearerToken($bindToken) : null;
            if (!$user) {
                return $this->redirectToFrontend([
                    'oauth_error' => 'bind_token_invalid',
                ], $redirect);
            }
            $stateData['bind_user_id'] = $user->id;
        }

        try {
            $url = $this->service->buildAuthorizationUrl($provider, $stateData);
        } catch (Throwable $e) {
            Log::error('OAuth redirect failed', ['error' => $e->getMessage()]);
            return $this->redirectToFrontend([
                'oauth_error' => 'redirect_failed',
            ], $redirect);
        }

        return redirect()->away($url);
    }

    /**
     * GET/POST /api/v1/passport/oauth/{identifier}/callback
     */
    public function callback(Request $request, string $identifier): RedirectResponse
    {
        // IdP 报错
        if ($request->input('error')) {
            return $this->redirectToFrontend([
                'oauth_error' => $request->input('error'),
            ]);
        }

        $state = (string) $request->input('state');
        $code = (string) $request->input('code');
        if (!$state || !$code) {
            return $this->redirectToFrontend(['oauth_error' => 'missing_params']);
        }

        $stateKey = CacheKey::get('OAUTH_STATE', $state);
        $stateData = Cache::pull($stateKey);
        if (!is_array($stateData)) {
            return $this->redirectToFrontend(['oauth_error' => 'state_invalid']);
        }
        if (($stateData['identifier'] ?? null) !== $identifier) {
            return $this->redirectToFrontend(['oauth_error' => 'state_mismatch']);
        }

        try {
            $provider = $this->service->resolveEnabledByIdentifier($identifier);
        } catch (Throwable $e) {
            return $this->redirectToFrontend(['oauth_error' => 'provider_not_found']);
        }

        try {
            $tokenResponse = $this->service->exchangeCode($provider, $code, $stateData['code_verifier']);
            $idTokenPayload = $this->service->parseIdToken(
                $tokenResponse['id_token'] ?? null,
                $provider,
                $stateData['nonce']
            );
            $userInfo = $this->service->fetchUserInfo($provider, $tokenResponse['access_token']);
            $profile = $this->service->extractProfile($provider, $idTokenPayload, $userInfo);
        } catch (Throwable $e) {
            Log::warning('OAuth callback failed', [
                'provider' => $identifier,
                'error' => $e->getMessage(),
            ]);
            return $this->redirectToFrontend(['oauth_error' => 'token_exchange_failed'], $stateData['redirect'] ?? null);
        }

        $intent = $stateData['intent'] ?? 'login';
        $redirect = $stateData['redirect'] ?? null;

        if ($intent === 'bind') {
            $user = \App\Models\User::find($stateData['bind_user_id'] ?? 0);
            if (!$user) {
                return $this->redirectToFrontend(['oauth_error' => 'bind_user_missing'], $redirect);
            }
            $result = $this->service->bindToUser($provider, $user, $profile);
            return match ($result['kind']) {
                'ok' => $this->redirectToFrontend(['oauth_bind_ok' => $provider->identifier], $redirect ?? 'profile'),
                'in_use_by_other' => $this->redirectToFrontend(['oauth_error' => 'identity_in_use'], $redirect ?? 'profile'),
                'user_already_bound' => $this->redirectToFrontend(['oauth_error' => 'user_already_bound'], $redirect ?? 'profile'),
                default => $this->redirectToFrontend(['oauth_error' => 'bind_failed'], $redirect ?? 'profile'),
            };
        }

        // login intent
        try {
            $result = $this->service->handleLogin($provider, $profile);
        } catch (Throwable $e) {
            Log::warning('OAuth login handle failed', ['error' => $e->getMessage()]);
            return $this->redirectToFrontend(['oauth_error' => 'login_failed'], $redirect);
        }

        switch ($result['kind']) {
            case 'exists':
            case 'registered':
                $user = $result['user'];
                $user->last_login_at = time();
                $user->save();
                $verify = Helper::guid();
                Cache::put(CacheKey::get('TEMP_TOKEN', $verify), $user->id, 60);
                return $this->redirectToFrontend([
                    'oauth_verify' => $verify,
                    'redirect' => $redirect ?? 'dashboard',
                ]);

            case 'email_conflict':
                return $this->redirectToFrontend([
                    'oauth_bind' => $result['candidate_token'],
                    'email' => $result['email'],
                ]);

            case 'register_blocked':
                return $this->redirectToFrontend(['oauth_error' => 'registration_disabled']);

            case 'no_email':
                return $this->redirectToFrontend(['oauth_error' => 'no_email_in_profile']);

            default:
                return $this->redirectToFrontend(['oauth_error' => 'login_failed']);
        }
    }

    /**
     * 把用户带回前端 /#/login (或其他 path)，参数追加到 hash 后面。
     * 复用现有 token2Login verify 流程：oauth_verify -> Login 页 -> /passport/auth/token2Login。
     */
    private function redirectToFrontend(array $params, ?string $redirect = null): RedirectResponse
    {
        $base = rtrim((string) admin_setting('app_url', url('/')), '/');
        $hashPath = $redirect && !str_starts_with($redirect, '/')
            ? '/' . $redirect
            : ($redirect ?: '/login');

        // 登录后我们要走 verify 流程，把用户带去 /login 让它处理 oauth_verify
        if (isset($params['oauth_verify'])) {
            $hashPath = '/login';
        }
        if (isset($params['oauth_bind'])) {
            $hashPath = '/login';
        }
        if (isset($params['oauth_bind_ok']) || (isset($params['oauth_error']) && $hashPath === '/login' && $redirect === 'profile')) {
            $hashPath = '/profile';
        }

        $url = $base . '/#' . $hashPath . '?' . http_build_query($params);
        return redirect()->away($url);
    }
}
