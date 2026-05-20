<?php

namespace App\Http\Controllers\V1\Passport;

use App\Http\Controllers\Controller;
use App\Models\OAuthProvider;
use App\Models\User;
use App\Services\Auth\OAuthService;
use App\Services\AuthService;
use App\Utils\CacheKey;
use App\Utils\Helper;
use Illuminate\Http\JsonResponse;
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
     * 公开列表，user 端 / admin 端的 Login 都会拉。
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
     * POST /api/v1/passport/oauth/verify
     * body: { verify: "<code>" }
     * 把回调时种下的 TEMP_TOKEN 换成 Bearer。专门服务 OAuth，跟 mail-link 的 token2Login 分开。
     */
    public function verify(Request $request): JsonResponse
    {
        $params = $request->validate([
            'verify' => 'required|string|size:32',
        ]);

        $key = CacheKey::get('TEMP_TOKEN', $params['verify']);
        $userId = Cache::pull($key);
        if (!$userId) {
            return $this->fail([400, 'verify 无效或已过期']);
        }

        $user = User::find($userId);
        if (!$user) {
            return $this->fail([400, '用户不存在']);
        }

        $authService = new AuthService($user);
        return $this->success($authService->generateAuthData());
    }

    /**
     * GET /api/v1/passport/oauth/{identifier}/redirect
     * query:
     *   intent=login|bind
     *   flow=user|admin   (admin 流要求 is_admin，回跳到 /{secure_path}#/login)
     *   bind_token=<bearer>  (intent=bind 时必填)
     *   redirect=<hash path>  (登录成功后想去的 hash，默认 login)
     */
    public function redirect(Request $request, string $identifier): RedirectResponse
    {
        $flow = $request->input('flow') === 'admin' ? 'admin' : 'user';

        try {
            $provider = $this->service->resolveEnabledByIdentifier($identifier);
        } catch (Throwable $e) {
            return $this->redirectToFrontend(['oauth_error' => 'provider_not_found'], null, $flow);
        }

        $intent = $request->input('intent', 'login') === 'bind' ? 'bind' : 'login';
        $redirect = (string) $request->input('redirect', $intent === 'bind' ? 'profile' : 'dashboard');

        $stateData = [
            'intent' => $intent,
            'flow' => $flow,
            'redirect' => $redirect,
            'ip' => $request->ip(),
        ];

        if ($intent === 'bind') {
            if (!$provider->allow_bind) {
                return $this->redirectToFrontend(['oauth_error' => 'bind_disabled'], $redirect, $flow);
            }
            $bindToken = (string) $request->input('bind_token');
            $user = $bindToken ? AuthService::findUserByBearerToken($bindToken) : null;
            if (!$user) {
                return $this->redirectToFrontend(['oauth_error' => 'bind_token_invalid'], $redirect, $flow);
            }
            $stateData['bind_user_id'] = $user->id;
        }

        try {
            $url = $this->service->buildAuthorizationUrl($provider, $stateData);
        } catch (Throwable $e) {
            Log::error('OAuth redirect failed', ['error' => $e->getMessage()]);
            return $this->redirectToFrontend(['oauth_error' => 'redirect_failed'], $redirect, $flow);
        }

        return redirect()->away($url);
    }

    /**
     * GET/POST /api/v1/passport/oauth/{identifier}/callback
     */
    public function callback(Request $request, string $identifier): RedirectResponse
    {
        if ($request->input('error')) {
            return $this->redirectToFrontend(['oauth_error' => $request->input('error')]);
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

        $flow = ($stateData['flow'] ?? 'user') === 'admin' ? 'admin' : 'user';
        $redirect = $stateData['redirect'] ?? null;

        try {
            $provider = $this->service->resolveEnabledByIdentifier($identifier);
        } catch (Throwable $e) {
            return $this->redirectToFrontend(['oauth_error' => 'provider_not_found'], $redirect, $flow);
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
            return $this->redirectToFrontend(['oauth_error' => 'token_exchange_failed'], $redirect, $flow);
        }

        $intent = $stateData['intent'] ?? 'login';

        if ($intent === 'bind') {
            $user = User::find($stateData['bind_user_id'] ?? 0);
            if (!$user) {
                return $this->redirectToFrontend(['oauth_error' => 'bind_user_missing'], $redirect, $flow);
            }
            $result = $this->service->bindToUser($provider, $user, $profile);
            return match ($result['kind']) {
                'ok' => $this->redirectToFrontend(['oauth_bind_ok' => $provider->identifier], $redirect ?? 'profile', $flow),
                'in_use_by_other' => $this->redirectToFrontend(['oauth_error' => 'identity_in_use'], $redirect ?? 'profile', $flow),
                'user_already_bound' => $this->redirectToFrontend(['oauth_error' => 'user_already_bound'], $redirect ?? 'profile', $flow),
                default => $this->redirectToFrontend(['oauth_error' => 'bind_failed'], $redirect ?? 'profile', $flow),
            };
        }

        // login intent
        try {
            $result = $this->service->handleLogin($provider, $profile, [
                // admin flow 永远不自动建账号
                'block_register' => $flow === 'admin',
            ]);
        } catch (Throwable $e) {
            Log::warning('OAuth login handle failed', ['error' => $e->getMessage()]);
            return $this->redirectToFrontend(['oauth_error' => 'login_failed'], $redirect, $flow);
        }

        switch ($result['kind']) {
            case 'exists':
            case 'registered':
                /** @var User $user */
                $user = $result['user'];

                // admin flow 必须是管理员才放行
                if ($flow === 'admin' && !$user->is_admin) {
                    return $this->redirectToFrontend(['oauth_error' => 'not_admin'], $redirect, $flow);
                }

                $user->last_login_at = time();
                $user->save();
                $verify = Helper::guid();
                Cache::put(CacheKey::get('TEMP_TOKEN', $verify), $user->id, 60);
                return $this->redirectToFrontend([
                    'oauth_verify' => $verify,
                    'redirect' => $redirect ?? 'dashboard',
                ], null, $flow);

            case 'email_conflict':
                // 邮箱冲突一定要走密码登录后再绑定（防 IdP 邮箱不可信劫持）。
                // 这个流程只有用户端 Login 页能处理（admin 端没"先登录再绑定"逻辑），
                // 所以强制走用户端。
                return $this->redirectToFrontend([
                    'oauth_bind' => $result['candidate_token'],
                    'email' => $result['email'],
                ], null, 'user');

            case 'register_blocked':
                // admin flow 强制不注册，错误码区分开（让前端文案更准）
                return $this->redirectToFrontend(
                    ['oauth_error' => $flow === 'admin' ? 'not_admin' : 'registration_disabled'],
                    null,
                    $flow
                );

            case 'no_email':
                return $this->redirectToFrontend(['oauth_error' => 'no_email_in_profile'], null, $flow);

            default:
                return $this->redirectToFrontend(['oauth_error' => 'login_failed'], null, $flow);
        }
    }

    /**
     * 把用户带回 user / admin 前端，参数追加到 hash 后面。
     * - user flow:   {app_url}/#/<hash>?...
     * - admin flow:  {app_url}/{secure_path}/#/<hash>?...
     */
    private function redirectToFrontend(array $params, ?string $redirect = null, string $flow = 'user'): RedirectResponse
    {
        $base = rtrim((string) admin_setting('app_url', url('/')), '/');

        if ($flow === 'admin') {
            $securePath = admin_setting('secure_path', admin_setting('frontend_admin_path', hash('crc32b', config('app.key'))));
            $base .= '/' . trim((string) $securePath, '/');
        }

        $hashPath = $redirect && !str_starts_with($redirect, '/')
            ? '/' . $redirect
            : ($redirect ?: '/login');

        // verify / bind 一定回到 login 页处理
        if (isset($params['oauth_verify']) || isset($params['oauth_bind'])) {
            $hashPath = '/login';
        }
        // user flow 下 bind_ok 跳到 profile（admin 端没 profile 这页，保持 login）
        if ($flow === 'user' && (isset($params['oauth_bind_ok'])
            || (isset($params['oauth_error']) && $redirect === 'profile'))) {
            $hashPath = '/profile';
        }

        $url = $base . '/#' . $hashPath . '?' . http_build_query($params);
        return redirect()->away($url);
    }
}
